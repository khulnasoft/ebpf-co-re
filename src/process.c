#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/wait.h>

#include <linux/version.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "khulnasoft_defs.h"
#include "khulnasoft_tests.h"
#include "khulnasoft_core_common.h"
#include "khulnasoft_process.h"

#include "process.skel.h"

enum core_process {
    PROCESS_RELEASE_TASK_NAME,
    PROCESS_SYS_CLONE,
    PROCESS_SYS_CLONE3,
    PROCESS_SYS_FORK,
    PROCESS_KERNEL_CLONE,
};

static char *names[] = {
    "release_task",
    "__x64_sys_clone",
    "__x64_sys_clone3",
    "_do_fork",
    "kernel_clone"
};

static void ebpf_disable_probes(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_release_task_probe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_do_fork_probe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_kernel_clone_probe, false);
}

static void ebpf_disable_tracepoints(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_clone_exit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_clone3_exit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_fork_exit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfork_exit, false);
}

static void ebpf_disable_trampoline(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_release_task_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_clone_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_clone3_fexit, false);
}

static void ebpf_set_trampoline_target(struct process_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.khulnasoft_release_task_fentry, 0,
                                   names[PROCESS_RELEASE_TASK_NAME]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_clone_fexit, 0,
                                   names[PROCESS_SYS_CLONE]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_clone3_fexit, 0,
                                   names[PROCESS_SYS_CLONE3]);
}

#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,3,0))
// https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8f6ccf6159aed1f04c6d179f61f6fb2691261e84
static inline void ebpf_disable_clone3(struct process_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_clone3_exit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_clone3_fexit, false);
}
#endif

static inline int process_attach_kprobe_target(struct process_bpf *obj)
{
    obj->links.khulnasoft_release_task_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_release_task_probe,
                                                                    false, names[PROCESS_RELEASE_TASK_NAME]);
    int ret = libbpf_get_error(obj->links.khulnasoft_release_task_probe);
    if (ret)
        goto endakt;

#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,9,16))
    obj->links.khulnasoft_do_fork_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_do_fork_probe,
                                                                    false, names[PROCESS_SYS_FORK]);
    ret = libbpf_get_error(obj->links.khulnasoft_do_fork_probe);
#else
    obj->links.khulnasoft_kernel_clone_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_kernel_clone_probe,
                                                                    false, names[PROCESS_KERNEL_CLONE]);
    ret = libbpf_get_error(obj->links.khulnasoft_kernel_clone_probe);
#endif
endakt:
    return ret;
}

static inline int ebpf_load_and_attach(struct process_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);
        ebpf_disable_tracepoints(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == KHULNASOFT_MODE_PROBE) {  // kprobe
        ebpf_disable_tracepoints(obj);
        ebpf_disable_trampoline(obj);

#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,9,16))
    bpf_program__set_autoload(obj->progs.khulnasoft_kernel_clone_probe, false);
#else
    bpf_program__set_autoload(obj->progs.khulnasoft_do_fork_probe, false);
#endif        
    } else { // tracepoint
        ebpf_disable_probes(obj);
        ebpf_disable_trampoline(obj);
    }

#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,3,0))
    ebpf_disable_clone3(obj);
#endif

    int ret = process_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector != KHULNASOFT_MODE_PROBE)
        ret = process_bpf__attach(obj);
    else
        ret = process_attach_kprobe_target(obj);

    if (!ret) {
        fprintf(stdout, "Process loaded with success\n");
    }

    return ret;
}

static pid_t ebpf_update_tables(int global, int apps)
{
    pid_t pid = ebpf_fill_global(global);

    struct khulnasoft_pid_stat_t stats = { .pid = pid, .tgid = pid, .exit_call = 1, .release_call = 1,
                                        .create_process = 1, .create_thread = 1, .task_err = 1 };

    uint32_t idx;
    for (idx = 0 ; idx < KHULNASOFT_EBPF_CORE_MIN_STORE; idx++) {
        int ret = bpf_map_update_elem(apps, &idx, &stats, 0);
        if (ret)
            fprintf(stderr, "Cannot insert value to global table.");
    }

    return pid;
}

static int process_read_apps_array(int fd, int ebpf_nprocs, uint32_t child)
{
    struct khulnasoft_pid_stat_t stored[ebpf_nprocs];

    uint64_t counter = 0;
    int key, next_key;
    key = next_key = 0;
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
            counter++;
        }
        memset(stored, 0, ebpf_nprocs*sizeof(struct khulnasoft_pid_stat_t));

        key = next_key;
    }

    if (counter) {
        fprintf(stdout, "Apps data stored with success. It collected %lu pids\n", counter);
        return 0;
    }

    return 2;
}


static int ebpf_process_tests(int selector, enum khulnasoft_apps_level map_level)
{
    struct process_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = KHULNASOFT_CORE_PROCESS_NUMBER;

    obj = process_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != KHULNASOFT_MODE_PROBE) {
        process_bpf__destroy(obj);

        obj = process_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = KHULNASOFT_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        int fd = bpf_map__fd(obj->maps.process_ctrl);
        ebpf_core_fill_ctrl(obj->maps.process_ctrl, map_level);

        fd = bpf_map__fd(obj->maps.tbl_total_stats);
        int fd2 = bpf_map__fd(obj->maps.tbl_pid_stats);
        pid_t my_pid = ebpf_update_tables(fd, fd2);
        // Wait data from more processes
        sleep(60);

        ret =  ebpf_read_global_array(fd, ebpf_nprocs, KHULNASOFT_GLOBAL_COUNTER);
        if (!ret) {
            ret = process_read_apps_array(fd2, ebpf_nprocs, (uint32_t)my_pid);
            if (ret)
                fprintf(stdout, "Empty apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", KHULNASOFT_CORE_DEFAULT_ERROR);
    }

    process_bpf__destroy(obj);

    return ret;
load_error:
    fprintf(stderr, "Cannot open or load BPF object\n");
    return 2;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  0 },
        {"probe",       no_argument,    0,  0 },
        {"tracepoint",  no_argument,    0,  0 },
        {"trampoline",  no_argument,    0,  0 },
        {"pid",         required_argument,    0,  0 },
        {0,             no_argument, 0, 0}
    };

    int selector = KHULNASOFT_MODE_TRAMPOLINE;
    int option_index = 0;
    enum khulnasoft_apps_level map_level = KHULNASOFT_APPS_LEVEL_REAL_PARENT;
    while (1) {
        int c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {
            case KHULNASOFT_EBPF_CORE_IDX_HELP: {
                          ebpf_core_print_help(argv[0], "mount", 1, 1);
                          exit(0);
                      }
            case KHULNASOFT_EBPF_CORE_IDX_PROBE: {
                          selector = KHULNASOFT_MODE_PROBE;
                          break;
                      }
            case KHULNASOFT_EBPF_CORE_IDX_TRACEPOINT: {
                          selector = KHULNASOFT_MODE_TRACEPOINT;
                          break;
                      }
            case KHULNASOFT_EBPF_CORE_IDX_TRAMPOLINE: {
                          selector = KHULNASOFT_MODE_TRAMPOLINE;
                          break;
                      }
            case KHULNASOFT_EBPF_CORE_IDX_PID: {
                          int user_input = (int)strtol(optarg, NULL, 10);
                          map_level = ebpf_check_map_level(user_input);
                          break;
                      }
            default: {
                         break;
                     }
        }
    }

    // Adjust memory
    int ret = khulnasoft_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    libbpf_set_print(khulnasoft_libbpf_vfprintf);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_process_tests(selector, map_level) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }
    return 0;
}

