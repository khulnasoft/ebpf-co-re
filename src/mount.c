#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/mount.h>

#include "khulnasoft_defs.h"
#include "khulnasoft_tests.h"
#include "khulnasoft_core_common.h"
#include "khulnasoft_mount.h"

#include "mount.skel.h"

enum khulnasoft_mount_syscalls {
    KHULNASOFT_MOUNT_SYSCALL,
    KHULNASOFT_UMOUNT_SYSCALL,

    KHULNASOFT_MOUNT_SYSCALLS_END
};

char *syscalls[] = { "__x64_sys_mount",
                     "__x64_sys_umount" };

static int attach_probe(struct mount_bpf *obj)
{
    obj->links.khulnasoft_mount_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_mount_probe,
                                                                false, syscalls[KHULNASOFT_MOUNT_SYSCALL]);
    int ret = libbpf_get_error(obj->links.khulnasoft_mount_probe);
    if (ret)
        return -1;

    obj->links.khulnasoft_mount_retprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_mount_retprobe,
                                                                   true, syscalls[KHULNASOFT_MOUNT_SYSCALL]);
    ret = libbpf_get_error(obj->links.khulnasoft_mount_retprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_umount_probe = bpf_program__attach_kprobe(obj->progs.khulnasoft_umount_probe,
                                                                 false, syscalls[KHULNASOFT_UMOUNT_SYSCALL]);
    ret = libbpf_get_error(obj->links.khulnasoft_umount_probe);
    if (ret)
        return -1;

    obj->links.khulnasoft_umount_retprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_umount_retprobe,
                                                                    true, syscalls[KHULNASOFT_UMOUNT_SYSCALL]);
    ret = libbpf_get_error(obj->links.khulnasoft_umount_retprobe);
    if (ret)
        return -1;

    return 0;
}

static inline void khulnasoft_ebpf_disable_probe(struct mount_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_mount_probe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_mount_retprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_umount_probe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_umount_retprobe, false);
}

static inline void khulnasoft_ebpf_disable_tracepoint(struct mount_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_mount_exit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_umount_exit, false);
}

static inline void khulnasoft_ebpf_disable_trampoline(struct mount_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_mount_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_umount_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_mount_fexit, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_umount_fexit, false);
}

static inline void khulnasoft_set_trampoline_target(struct mount_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.khulnasoft_mount_fentry, 0,
                                   syscalls[KHULNASOFT_MOUNT_SYSCALL]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_mount_fexit, 0,
                                   syscalls[KHULNASOFT_MOUNT_SYSCALL]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_umount_fentry, 0,
                                   syscalls[KHULNASOFT_UMOUNT_SYSCALL]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_umount_fexit, 0,
                                   syscalls[KHULNASOFT_UMOUNT_SYSCALL]);
}

static inline int ebpf_load_and_attach(struct mount_bpf *obj, int selector)
{
    if (!selector) { //trampoline
        khulnasoft_ebpf_disable_probe(obj);
        khulnasoft_ebpf_disable_tracepoint(obj);

        khulnasoft_set_trampoline_target(obj);
    } else if (selector == 1) { // probe
        khulnasoft_ebpf_disable_trampoline(obj);
        khulnasoft_ebpf_disable_tracepoint(obj);
    } else { // tracepoint
        khulnasoft_ebpf_disable_probe(obj);
        khulnasoft_ebpf_disable_trampoline(obj);
    }

    int ret = mount_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (selector == 1) // attach kprobe
        ret = attach_probe(obj);
    else {
        ret = mount_bpf__attach(obj);
    }

    if (!ret) {
        fprintf(stdout, "%s loaded with success\n", (selector) ? "tracepoint" : "probe");
    }

    return ret;
}

static int call_syscalls()
{
    char *dst = { "./mydst" };
    if (mkdir(dst, 0777)) {
        fprintf(stdout, "Cannot create directory\n");
        return -1;
    }

    // I am not testing return, because errors are also stored at hash map
    (void)mount("none", dst, "tmpfs", 0, "mode=0777");
    (void)umount(dst);

    rmdir(dst);

    return 0;
}

static int mount_read_array(int fd)
{
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = KHULNASOFT_CORE_PROCESS_NUMBER;
    uint64_t stored[ebpf_nprocs];

    uint32_t idx;
    uint64_t counter = 0;
    for (idx = 0; idx < KHULNASOFT_MOUNT_END; idx++)  {
        if (!bpf_map_lookup_elem(fd, &idx, stored)) {
            int j;
            for (j = 0; j < ebpf_nprocs; j++) {
                counter += stored[j];
            }
        }

        memset(stored, 0, sizeof(uint64_t) * ebpf_nprocs);
    }

    if (counter >= 2) {
        fprintf(stdout, "Data stored with success\n");
        return 0;
    }

    return 2;
}

static int ebpf_mount_tests(int selector)
{
    struct mount_bpf *obj = NULL;

    obj = mount_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != KHULNASOFT_MODE_PROBE) {
        mount_bpf__destroy(obj);

        obj = mount_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = KHULNASOFT_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        ret = call_syscalls();
        if (!ret) {
            int fd = bpf_map__fd(obj->maps.tbl_mount);
            ret = mount_read_array(fd);
        }
    } else {
        ret = 3;
        fprintf(stderr ,"%s", KHULNASOFT_CORE_DEFAULT_ERROR);
    }

    mount_bpf__destroy(obj);

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
        {0, 0, 0, 0}
    };

    int selector = 0;
    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {    
            case KHULNASOFT_EBPF_CORE_IDX_HELP: {
                          ebpf_core_print_help(argv[0], "mount", 1, 0);
                          exit(0);
                      }
            case KHULNASOFT_EBPF_CORE_IDX_PROBE: {
                          selector = KHULNASOFT_MODE_PROBE;
                          break;
                      }
            case KHULNASOFT_EBPF_CORE_IDX_TRACEPOINT: {
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead.\n");
                          selector = KHULNASOFT_MODE_PROBE;
                          break;
                      }
            case KHULNASOFT_EBPF_CORE_IDX_TRAMPOLINE: {
                          selector = KHULNASOFT_MODE_TRAMPOLINE;
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
        if (bf)
            selector = ebpf_find_functions(bf, selector, syscalls, KHULNASOFT_MOUNT_SYSCALLS_END);
    }

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_mount_tests(selector) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }

    return 0;
}

