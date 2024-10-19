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
#include "khulnasoft_dc.h"

#include "dc.skel.h"

char *function_list[] = { "lookup_fast",
                          "d_lookup"
};
// This preprocessor is defined here, because it is not useful in kernel-colector
#define KHULNASOFT_DCSTAT_RELEASE_TASK 2

static inline void ebpf_disable_probes(struct dc_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_lookup_fast_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_d_lookup_kretprobe, false);
}

static inline void ebpf_disable_trampoline(struct dc_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_lookup_fast_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_d_lookup_fexit, false);
}

static void ebpf_set_trampoline_target(struct dc_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.khulnasoft_lookup_fast_fentry, 0,
                                   function_list[KHULNASOFT_LOOKUP_FAST]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_d_lookup_fexit, 0,
                                   function_list[KHULNASOFT_D_LOOKUP]);
}

static int ebpf_attach_probes(struct dc_bpf *obj)
{
    obj->links.khulnasoft_d_lookup_kretprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_d_lookup_kretprobe,
                                                                       true, function_list[KHULNASOFT_D_LOOKUP]);
    int ret = libbpf_get_error(obj->links.khulnasoft_d_lookup_kretprobe);
    if (ret)
        return -1;

    obj->links.khulnasoft_lookup_fast_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_lookup_fast_kprobe,
                                                                       false, function_list[KHULNASOFT_LOOKUP_FAST]);
    ret = libbpf_get_error(obj->links.khulnasoft_lookup_fast_kprobe);
    if (ret)
        return -1;

    return 0;
}

static inline int ebpf_load_and_attach(struct dc_bpf *obj, int selector)
{
    // Adjust memory
    int ret;
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == KHULNASOFT_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    ret = dc_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    } 

    if (!selector) {
        ret = dc_bpf__attach(obj);
    } else {
        ret = ebpf_attach_probes(obj);
    }
    
    if (!ret) {
        fprintf(stdout, "Directory Cache loaded with success\n");
    }

    return ret;
}

static int dc_read_apps_array(int fd, int ebpf_nprocs)
{
    khulnasoft_dc_stat_t stored[ebpf_nprocs];

    uint32_t key, next_key;
    uint64_t counter = 0;
    key = next_key = 0;

    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
            counter++;
        }
        memset(stored, 0, ebpf_nprocs*sizeof(khulnasoft_dc_stat_t));

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

    khulnasoft_dc_stat_t stats = { .references = 1, .slow = 1, .missed = 1};

    uint32_t idx = (uint32_t)pid;
    int ret = bpf_map_update_elem(apps, &idx, &stats, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to apps table.");

    return pid;
}

static int ebpf_dc_tests(int selector, enum khulnasoft_apps_level map_level)
{
    struct dc_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = KHULNASOFT_CORE_PROCESS_NUMBER;

    obj = dc_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != KHULNASOFT_MODE_PROBE) {
        dc_bpf__destroy(obj);

        obj = dc_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = KHULNASOFT_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        int fd = bpf_map__fd(obj->maps.dcstat_ctrl);
        ebpf_core_fill_ctrl(obj->maps.dcstat_ctrl, map_level);

        fd = bpf_map__fd(obj->maps.dcstat_global);
        int fd2 = bpf_map__fd(obj->maps.dcstat_pid);
        (void)ebpf_update_tables(fd, fd2);
        sleep(60);

        ret =  ebpf_read_global_array(fd, ebpf_nprocs, KHULNASOFT_DIRECTORY_CACHE_END);
        if (!ret) {
            ret = dc_read_apps_array(fd2, ebpf_nprocs);
            if (ret)
                fprintf(stdout, "Empty apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        fprintf(stderr ,"%s", KHULNASOFT_CORE_DEFAULT_ERROR);
        ret = 3;
    }

    dc_bpf__destroy(obj);

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
                          ebpf_core_print_help(argv[0], "dc", 1, 1);
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

    int ret = khulnasoft_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    libbpf_set_print(khulnasoft_libbpf_vfprintf);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    char *lookup_fast = khulnasoft_update_name(function_list[KHULNASOFT_LOOKUP_FAST]);
    if (!lookup_fast) {
        return 2;
    }
    function_list[KHULNASOFT_LOOKUP_FAST] = lookup_fast;

    struct btf *bf = NULL;
    if (!selector) {
        bf = khulnasoft_parse_btf_file((const char *)KHULNASOFT_BTF_FILE);
        if (bf) {
            selector = ebpf_find_functions(bf, selector, function_list, KHULNASOFT_DC_COUNTER);
            btf__free(bf);
        }
    }

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_dc_tests(selector, map_level) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }

    free(lookup_fast);

    return 0;
}

