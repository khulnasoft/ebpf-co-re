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

#include "mdflush.skel.h"

enum khulnasoft_md_function_list {
    KHULNASOFT_MD_FLUSH_REQUEST,

    // Always insert before this value 
    KHULNASOFT_MD_END
};

char *function_list[] = { "md_flush_request" };

static inline void ebpf_disable_probes(struct mdflush_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_md_flush_request_kprobe, false);
}

static inline void ebpf_disable_trampoline(struct mdflush_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_md_flush_request_fentry, false);
}

static void ebpf_set_trampoline_target(struct mdflush_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.khulnasoft_md_flush_request_fentry, 0,
                                   function_list[KHULNASOFT_MD_FLUSH_REQUEST]);
}

static int ebpf_load_probes(struct mdflush_bpf *obj)
{
    obj->links.khulnasoft_md_flush_request_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_md_flush_request_kprobe,
                                                                            false, function_list[KHULNASOFT_MD_FLUSH_REQUEST]);
    int ret = libbpf_get_error(obj->links.khulnasoft_md_flush_request_kprobe);
    if (ret)
        return -1;

    return 0;
}

static inline int ebpf_load_and_attach(struct mdflush_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == KHULNASOFT_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    int ret = mdflush_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (!selector)
        ret = mdflush_bpf__attach(obj);
    else
        ret = ebpf_load_probes(obj);

    if (!ret) {
        fprintf(stdout, "md_flush_request loaded with success\n");
    }

    return ret;
}

static void ebpf_update_tables(int global)
{
    (void)ebpf_fill_global(global);
}

static int ebpf_mdflush_tests(int selector)
{
    struct mdflush_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = KHULNASOFT_CORE_PROCESS_NUMBER;

    obj = mdflush_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_mdflush);
        ebpf_update_tables(fd);

        ret =  ebpf_read_global_array(fd, ebpf_nprocs, 1);
        if (ret) 
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", KHULNASOFT_CORE_DEFAULT_ERROR);
    }

    mdflush_bpf__destroy(obj);

    return ret;
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

    int selector = KHULNASOFT_MODE_TRAMPOLINE;
    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_core_print_help(argv[0], "mdflush", 1, 0);
                          exit(0);
                      }
            case 'p': {
                          selector = KHULNASOFT_MODE_PROBE;
                          break;
                      }
            case 'r': {
                          selector = KHULNASOFT_MODE_PROBE;
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
                          break;
                      }
            case 't': {
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

    char *md_flush_request = khulnasoft_update_name(function_list[KHULNASOFT_MD_FLUSH_REQUEST]);
    if (!md_flush_request) {
        fprintf(stderr, "Module `md` is not loaded, so it is not possible to monitor calls for md_flush_request.\n");
        return -1;
    }
    function_list[KHULNASOFT_MD_FLUSH_REQUEST] = md_flush_request;

    struct btf *bf = NULL;
    if (!selector) {
        bf = khulnasoft_parse_btf_file((const char *)KHULNASOFT_BTF_FILE);
        if (bf) {
            selector = ebpf_find_functions(bf, selector, function_list, KHULNASOFT_MD_END);
            btf__free(bf);
        }
    }

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_mdflush_tests(selector) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }

    free(md_flush_request);

    return 0;
}

