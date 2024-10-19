#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "khulnasoft_defs.h"
#include "khulnasoft_tests.h"
#include "khulnasoft_core_common.h"
#include "khulnasoft_vfs.h"

#include "vfs.skel.h"

char *function_list[] = { "vfs_write",
                          "vfs_writev",
                          "vfs_read",
                          "vfs_readv",
                          "vfs_unlink",
                          "vfs_fsync",
                          "vfs_open",
                          "vfs_create"
};
// This preprocessor is defined here, because it is not useful in kernel-colector
#define KHULNASOFT_VFS_RELEASE_TASK 8

static inline void ebpf_disable_probes(struct vfs_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_write_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_write_kretprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_writev_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_writev_kretprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_read_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_read_kretprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_readv_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_readv_kretprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_unlink_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_unlink_kretprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_fsync_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_fsync_kretprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_open_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_open_kretprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_create_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_create_kretprobe, false);
}

static inline void ebpf_disable_trampoline(struct vfs_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_write_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_write_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_writev_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_writev_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_read_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_read_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_readv_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_readv_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_unlink_fentry, false);
//    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_unlink_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_fsync_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_fsync_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_open_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_open_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_create_fentry, false);
//    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_create_fexit, false);
}

static void ebpf_set_trampoline_target(struct vfs_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_write_fentry, 0,
                                   function_list[KHULNASOFT_VFS_WRITE]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_write_fexit, 0,
                                   function_list[KHULNASOFT_VFS_WRITE]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_writev_fentry, 0,
                                   function_list[KHULNASOFT_VFS_WRITEV]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_writev_fexit, 0,
                                   function_list[KHULNASOFT_VFS_WRITEV]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_read_fentry, 0,
                                   function_list[KHULNASOFT_VFS_READ]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_read_fexit, 0,
                                   function_list[KHULNASOFT_VFS_READ]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_readv_fentry, 0,
                                   function_list[KHULNASOFT_VFS_READV]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_readv_fexit, 0,
                                   function_list[KHULNASOFT_VFS_READV]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_unlink_fentry, 0,
                                   function_list[KHULNASOFT_VFS_UNLINK]);

//    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_unlink_fexit, 0,
//                                   function_list[KHULNASOFT_VFS_UNLINK]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_fsync_fentry, 0,
                                   function_list[KHULNASOFT_VFS_FSYNC]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_fsync_fexit, 0,
                                   function_list[KHULNASOFT_VFS_FSYNC]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_open_fentry, 0,
                                   function_list[KHULNASOFT_VFS_OPEN]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_open_fexit, 0,
                                   function_list[KHULNASOFT_VFS_OPEN]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_create_fentry, 0,
                                   function_list[KHULNASOFT_VFS_CREATE]);

//    bpf_program__set_attach_target(obj->progs.khulnasoft_vfs_create_fexit, 0,
//                                   function_list[KHULNASOFT_VFS_CREATE]);
}

#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,6,0))
static void ebpf_disable_specific_trampoline(struct vfs_bpf *obj)
{
//    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_unlink_fexit, false);
//    bpf_program__set_autoload(obj->progs.khulnasoft_vfs_create_fexit, false);
}
#endif

static int ebpf_attach_probes(struct vfs_bpf *obj)
{
    obj->links.khulnasoft_vfs_write_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_write_kprobe,
                                                                     false, function_list[KHULNASOFT_VFS_WRITE]);
    int ret = libbpf_get_error(obj->links.khulnasoft_vfs_write_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_write_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_write_kretprobe,
                                                                        true, function_list[KHULNASOFT_VFS_WRITE]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_write_kretprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_writev_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_writev_kprobe,
                                                                      false, function_list[KHULNASOFT_VFS_WRITEV]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_writev_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_writev_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_writev_kretprobe,
                                                                         true, function_list[KHULNASOFT_VFS_WRITEV]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_writev_kretprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_read_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_read_kprobe,
                                                                    false, function_list[KHULNASOFT_VFS_READ]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_read_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_read_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_read_kretprobe,
                                                                       true, function_list[KHULNASOFT_VFS_READ]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_read_kretprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_readv_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_readv_kprobe,
                                                                     false, function_list[KHULNASOFT_VFS_READV]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_readv_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_readv_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_readv_kretprobe,
                                                                        true, function_list[KHULNASOFT_VFS_READV]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_readv_kretprobe);
    if (ret)
        return -1;
 
    obj->links.khulnasoft_vfs_unlink_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_unlink_kprobe,
                                                                      false, function_list[KHULNASOFT_VFS_UNLINK]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_unlink_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_unlink_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_unlink_kretprobe,
                                                                         true, function_list[KHULNASOFT_VFS_UNLINK]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_unlink_kretprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_fsync_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_fsync_kprobe,
                                                                     false, function_list[KHULNASOFT_VFS_FSYNC]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_fsync_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_fsync_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_fsync_kretprobe,
                                                                        true, function_list[KHULNASOFT_VFS_FSYNC]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_fsync_kretprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_open_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_open_kprobe,
                                                                    false, function_list[KHULNASOFT_VFS_OPEN]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_open_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_open_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_open_kretprobe,
                                                                       true, function_list[KHULNASOFT_VFS_OPEN]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_open_kretprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_create_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_create_kprobe,
                                                                      false, function_list[KHULNASOFT_VFS_CREATE]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_create_kprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_vfs_create_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_vfs_create_kretprobe,
                                                                         true, function_list[KHULNASOFT_VFS_CREATE]);
    ret = libbpf_get_error(obj->links.khulnasoft_vfs_create_kretprobe);
    if (ret)
        return -1;
 
    return 0;
}

static inline int ebpf_load_and_attach(struct vfs_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);
#if (MY_LINUX_VERSION_CODE <= KERNEL_VERSION(5,6,0))
        ebpf_disable_specific_trampoline(obj);
#endif

        ebpf_set_trampoline_target(obj);
    } else if (selector == KHULNASOFT_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    int ret = vfs_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (!selector) {
        ret = vfs_bpf__attach(obj);
    } else {
        ret = ebpf_attach_probes(obj);
    }
    
    if (!ret) {
        fprintf(stdout, "VFS loaded with success\n");
    }

    return ret;
}

static int vfs_read_apps_array(int fd, int ebpf_nprocs, uint32_t my_pid)
{
    struct khulnasoft_vfs_stat_t stored[ebpf_nprocs];

    int key, next_key;
    key = next_key = 0;
    uint64_t counter = 0;
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
            counter++;
        }
        memset(stored, 0, ebpf_nprocs * sizeof(struct khulnasoft_vfs_stat_t));

        key = next_key;
    }

    if (counter) {
        fprintf(stdout, "Apps data stored with success. It collected %lu pids\n", counter);
        return 0;
    }

    return 2;
}

static pid_t ebpf_update_tables(int global, int apps)
{
    pid_t pid = ebpf_fill_global(global);

    struct khulnasoft_vfs_stat_t stats = { .ct = 0, .name = "vfs", .write_call = 1,
                                        .writev_call = 1, .read_call = 1, .readv_call = 1, .unlink_call = 1,
                                        .fsync_call = 1, .open_call = 1, .create_call = 1, .write_bytes = 1,
                                        .writev_bytes = 1, .readv_bytes = 1, .read_bytes = 1, .write_err = 1,
                                        .writev_err = 1, .read_err = 1, .readv_err = 1, .unlink_err = 1,
                                        .fsync_err = 1, .open_err = 1, .create_err = 1 };

    uint32_t idx;
    for (idx = 0 ; idx < KHULNASOFT_EBPF_CORE_MIN_STORE; idx++) {
        int ret = bpf_map_update_elem(apps, &idx, &stats, 0);
        if (ret) {
            fprintf(stderr, "Cannot insert value to global table.");
            break;
        }
    }

    return pid;
}

static int ebpf_vfs_tests(int selector, enum khulnasoft_apps_level map_level)
{
    struct vfs_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = KHULNASOFT_CORE_PROCESS_NUMBER;

    obj = vfs_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != KHULNASOFT_MODE_PROBE) {
        vfs_bpf__destroy(obj);

        obj = vfs_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = KHULNASOFT_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        int fd = bpf_map__fd(obj->maps.vfs_ctrl);
        ebpf_core_fill_ctrl(obj->maps.vfs_ctrl, map_level);

        fd = bpf_map__fd(obj->maps.tbl_vfs_stats);
        int fd2 = bpf_map__fd(obj->maps.tbl_vfs_pid);
        pid_t my_pid = ebpf_update_tables(fd, fd2);

        sleep(60);
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, KHULNASOFT_VFS_COUNTER);
        if (!ret) {
            ret = vfs_read_apps_array(fd2, ebpf_nprocs, (uint32_t)my_pid);
            if (ret)
                fprintf(stdout, "Empty apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", KHULNASOFT_CORE_DEFAULT_ERROR);
    }


    vfs_bpf__destroy(obj);

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
        {0, 0, 0, 0}
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
                          ebpf_core_print_help(argv[0], "vfs", 1, 1);
                          exit(0);
                      }
            case KHULNASOFT_EBPF_CORE_IDX_PROBE: {
                          selector = KHULNASOFT_MODE_PROBE;
                          break;
                      }
            case KHULNASOFT_EBPF_CORE_IDX_TRACEPOINT: {
                          selector = KHULNASOFT_MODE_PROBE;
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
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
        if (bf) {
            selector = ebpf_find_functions(bf, selector, function_list, KHULNASOFT_VFS_END_LIST);
            btf__free(bf);
        }
    }

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_vfs_tests(selector, map_level) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }

    return 0;
}

