#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <sys/ipc.h>
#include <sys/shm.h>

#include "khulnasoft_defs.h"
#include "khulnasoft_tests.h"
#include "khulnasoft_core_common.h"
#include "khulnasoft_shm.h"

#include "shm.skel.h"

char *syscalls[] = { "__x64_sys_shmget",
                     "__x64_sys_shmat",
                     "__x64_sys_shmdt",
                     "__x64_sys_shmctl"
                                    };
// This preprocessor is defined here, because it is not useful in kernel-colector
#define KHULNASOFT_SHM_RELEASE_TASK 4

static void ebpf_disable_tracepoint(struct shm_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_syscall_shmget, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_syscall_shmat, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_syscall_shmdt, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_syscall_shmctl, false);
}

static void ebpf_disable_kprobe(struct shm_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_shmget_probe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_shmat_probe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_shmdt_probe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_shmctl_probe, false);
}

static void ebpf_disable_trampoline(struct shm_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_shmget_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_shmat_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_shmdt_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_shmctl_fentry, false);
}

static int ebpf_attach_kprobe(struct shm_bpf *obj)
{
    obj->links.khulnasoft_shmget_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_shmget_probe,
                                                                 false, syscalls[KHULNASOFT_KEY_SHMGET_CALL]);
    int ret = libbpf_get_error(obj->links.khulnasoft_shmget_probe);
    if (ret)
        return -1;

    obj->links.khulnasoft_shmat_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_shmat_probe,
                                                                false, syscalls[KHULNASOFT_KEY_SHMAT_CALL]);
    ret = libbpf_get_error(obj->links.khulnasoft_shmat_probe);
    if (ret)
        return -1;

    obj->links.khulnasoft_shmdt_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_shmdt_probe,
                                                                false, syscalls[KHULNASOFT_KEY_SHMDT_CALL]);
    ret = libbpf_get_error(obj->links.khulnasoft_shmdt_probe);
    if (ret)
        return -1;

    obj->links.khulnasoft_shmctl_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_shmctl_probe,
                                                                false, syscalls[KHULNASOFT_KEY_SHMCTL_CALL]);
    ret = libbpf_get_error(obj->links.khulnasoft_shmctl_probe);
    if (ret)
        return -1;

    return 0;
}

static void ebpf_set_trampoline_target(struct shm_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.khulnasoft_shmget_fentry, 0,
                                   syscalls[KHULNASOFT_KEY_SHMGET_CALL]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_shmat_fentry, 0,
                                   syscalls[KHULNASOFT_KEY_SHMAT_CALL]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_shmdt_fentry, 0,
                                   syscalls[KHULNASOFT_KEY_SHMDT_CALL]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_shmctl_fentry, 0,
                                   syscalls[KHULNASOFT_KEY_SHMCTL_CALL]);
}

static inline int ebpf_load_and_attach(struct shm_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_tracepoint(obj);
        ebpf_disable_kprobe(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == 1) { // kprobe
        ebpf_disable_tracepoint(obj);
        ebpf_disable_trampoline(obj);
    } else { // tracepoint
        ebpf_disable_kprobe(obj);
        ebpf_disable_trampoline(obj);
    }

    int ret = shm_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector != 1) // Not kprobe
        ret = shm_bpf__attach(obj);
    else
        ret = ebpf_attach_kprobe(obj);

    if (!ret) {
        char *method = ebpf_select_type(selector);
        fprintf(stdout, "%s loaded with success\n", method);
    }

    return ret;
}

/* This is kept to show how to use the syscalls
int call_syscalls()
{
#define SHMSZ   27
    // Copied and adapt from https://github.com/khulnasoft/khulnasoft/pull/11560#issuecomment-927613811
    key_t name = 5678;

    int shmid = shmget(name, SHMSZ, IPC_CREAT | 0666);
    if (shmid < 0)
         return 2;

    sleep(1);

    char *shm = shmat(shmid, NULL, 0);
    if (shm == (char *) -1) {
        perror("shmat");
        return 2;
    }

    char c, *s = shm;
    for (c = 'a'; c <= 'z'; c++)
        *s++ = c;
    *s = 0;

    sleep(1);

    struct shmid_ds dsbuf;
    if ((shmctl(shmid, IPC_STAT, &dsbuf)) == -1) {
        perror("shmctl");
        return 2;
    }

    if ((shmdt(shm)) == -1) {
        perror("shmdt");
        return 2;
    }

    return 0;
}
*/

void shm_fill_tables(struct shm_bpf *obj)
{
    int fd = bpf_map__fd(obj->maps.tbl_shm);
    uint32_t key;
    uint64_t global_data = 64;
    for (key = 0; key < KHULNASOFT_SHM_END; key++) {
        if (bpf_map_update_elem(fd, &key, &global_data, BPF_ANY))
            fprintf(stderr, "Cannot insert key %u\n", key);
    }

    fd = bpf_map__fd(obj->maps.tbl_pid_shm);
    khulnasoft_shm_t apps_data = { .get = 1, .at = 1, .dt = 1, .ctl = 1};
    for (key = 0; key < KHULNASOFT_EBPF_CORE_MIN_STORE; key++) {
        if (bpf_map_update_elem(fd, &key, &apps_data, BPF_ANY))
            fprintf(stderr, "Cannot insert key %u\n", key);
    }
}

static int shm_read_apps_array(int fd, int ebpf_nprocs)
{
    khulnasoft_shm_t stored[ebpf_nprocs];

    int key, next_key;
    key = next_key = 0;
    uint64_t counter = 0;
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
            counter++;
        }
        memset(stored, 0, ebpf_nprocs * sizeof(khulnasoft_shm_t));

        key = next_key;
    }

    if (counter) {
        fprintf(stdout, "Apps data stored with success. It collected %lu pids\n", counter);
        return 0;
    }

    return 2;
}

int ebpf_shm_tests(struct btf *bf, int selector, enum khulnasoft_apps_level map_level)
{
    struct shm_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = KHULNASOFT_CORE_PROCESS_NUMBER;

    if (bf)
        selector = ebpf_find_functions(bf, selector, syscalls, KHULNASOFT_SHM_END);

    obj = shm_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != KHULNASOFT_MODE_PROBE) {
        shm_bpf__destroy(obj);

        obj = shm_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = KHULNASOFT_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        int fd = bpf_map__fd(obj->maps.shm_ctrl);
        ebpf_core_fill_ctrl(obj->maps.shm_ctrl, map_level);

        //ret = call_syscalls();
        shm_fill_tables(obj);
        sleep(60);
        fd = bpf_map__fd(obj->maps.tbl_shm);
        ret = ebpf_read_global_array(fd, ebpf_nprocs, KHULNASOFT_SHM_END);
        if (!ret) {
            fd = bpf_map__fd(obj->maps.tbl_pid_shm);
            ret = shm_read_apps_array(fd, ebpf_nprocs);
        }
    } else {
        ret = 3;
        fprintf(stderr ,"%s", KHULNASOFT_CORE_DEFAULT_ERROR);
    }

    shm_bpf__destroy(obj);

    return ret;
load_error:
    fprintf(stderr, "Cannot open or load BPF object\n");
    return 2;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  'h' },
        {"probe",       no_argument,    0,  'p' },
        {"tracepoint",  no_argument,    0,  'r' },
        {"trampoline",  no_argument,    0,  't' },
        {"pid",         required_argument,    0,  0 },
        {0, 0, 0, 0}
    };

    // use trampoline as default
    int selector = KHULNASOFT_MODE_TRAMPOLINE;
    int option_index = 0;
    enum khulnasoft_apps_level map_level = KHULNASOFT_APPS_LEVEL_REAL_PARENT;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {
            case KHULNASOFT_EBPF_CORE_IDX_HELP: {
                          ebpf_core_print_help(argv[0], "shared_memory", 1, 1);
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
    
    struct btf *bf = NULL;
    if (!selector) {
        bf = khulnasoft_parse_btf_file((const char *)KHULNASOFT_BTF_FILE);
    }

    ret = ebpf_shm_tests(bf, selector, map_level);

    if (bf)
        btf__free(bf);

    return 0;
}

