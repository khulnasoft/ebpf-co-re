#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#include <linux/version.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>

#include "khulnasoft_defs.h"
#include "khulnasoft_tests.h"
#include "khulnasoft_core_common.h"
#include "khulnasoft_cache.h"

#include "cachestat.skel.h"

// Alma Linux modified internal name, this structure was brought for it.
static ebpf_specify_name_t cachestat_names[] = { {.program_name = "khulnasoft_folio_mark_dirty_kprobe",
                                                  .function_to_attach = "__folio_mark_dirty",
                                                  .length = 18,
                                                  .optional = NULL,
                                                  .retprobe = 0},
                                                 {.program_name = "khulnasoft_set_page_dirty_kprobe",
                                                  .function_to_attach = "__set_page_dirty",
                                                  .length = 16,
                                                  .optional = NULL,
                                                  .retprobe = 0},
                                                 {.program_name = "khulnasoft_account_page_dirtied_kprobe",
                                                  .function_to_attach = "account_page_dirtied",
                                                  .length = 20,
                                                  .optional = NULL,
                                                  .retprobe = 0},
                                                 {.program_name = NULL}};

char *cachestat_fcnt[] = { "add_to_page_cache_lru",
                     "mark_page_accessed",
                     NULL, // Filled after to discover available functions
                     "mark_buffer_dirty"
};
// This preprocessor is defined here, because it is not useful in kernel-colector
#define KHULNASOFT_CACHESTAT_RELEASE_TASK 4

static inline void khulnasoft_ebpf_disable_probe(struct cachestat_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_add_to_page_cache_lru_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_mark_page_accessed_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_folio_mark_dirty_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_set_page_dirty_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_account_page_dirtied_kprobe, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_mark_buffer_dirty_kprobe, false);
}

static inline void khulnasoft_ebpf_disable_specific_probe(struct cachestat_bpf *obj)
{
    if (cachestat_names[0].optional) {
        bpf_program__set_autoload(obj->progs.khulnasoft_account_page_dirtied_kprobe, false);
        bpf_program__set_autoload(obj->progs.khulnasoft_set_page_dirty_kprobe, false);
    } else if (cachestat_names[1].optional) {
        bpf_program__set_autoload(obj->progs.khulnasoft_folio_mark_dirty_kprobe, false);
        bpf_program__set_autoload(obj->progs.khulnasoft_account_page_dirtied_kprobe, false);
    } else {
        bpf_program__set_autoload(obj->progs.khulnasoft_folio_mark_dirty_kprobe, false);
        bpf_program__set_autoload(obj->progs.khulnasoft_set_page_dirty_kprobe, false);
    }
}

static inline void khulnasoft_ebpf_disable_trampoline(struct cachestat_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.khulnasoft_add_to_page_cache_lru_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_mark_page_accessed_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_folio_mark_dirty_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_set_page_dirty_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_account_page_dirtied_fentry, false);
    bpf_program__set_autoload(obj->progs.khulnasoft_mark_buffer_dirty_fentry, false);
}

static inline void khulnasoft_ebpf_disable_specific_trampoline(struct cachestat_bpf *obj)
{
    if (cachestat_names[0].optional) {
        bpf_program__set_autoload(obj->progs.khulnasoft_account_page_dirtied_fentry, false);
        bpf_program__set_autoload(obj->progs.khulnasoft_set_page_dirty_fentry, false);
    } else if (cachestat_names[1].optional) {
        bpf_program__set_autoload(obj->progs.khulnasoft_folio_mark_dirty_fentry, false);
        bpf_program__set_autoload(obj->progs.khulnasoft_account_page_dirtied_fentry, false);
    } else {
        bpf_program__set_autoload(obj->progs.khulnasoft_folio_mark_dirty_fentry, false);
        bpf_program__set_autoload(obj->progs.khulnasoft_set_page_dirty_fentry, false);
    }
}

static inline void khulnasoft_set_trampoline_target(struct cachestat_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.khulnasoft_add_to_page_cache_lru_fentry, 0,
                                   cachestat_fcnt[KHULNASOFT_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU]);

    bpf_program__set_attach_target(obj->progs.khulnasoft_mark_page_accessed_fentry, 0,
                                   cachestat_fcnt[KHULNASOFT_KEY_CALLS_MARK_PAGE_ACCESSED]);

    if (cachestat_names[0].optional) {
        bpf_program__set_attach_target(obj->progs.khulnasoft_folio_mark_dirty_fentry, 0,
                                   cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
    } else if (cachestat_names[1].optional) {
        bpf_program__set_attach_target(obj->progs.khulnasoft_set_page_dirty_fentry, 0,
                                   cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
    } else {
        bpf_program__set_attach_target(obj->progs.khulnasoft_account_page_dirtied_fentry, 0,
                                   cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
    }

    bpf_program__set_attach_target(obj->progs.khulnasoft_mark_buffer_dirty_fentry, 0,
                                   cachestat_fcnt[KHULNASOFT_KEY_CALLS_MARK_BUFFER_DIRTY]);
}

static inline int khulnasoft_attach_kprobe_target(struct cachestat_bpf *obj)
{
    obj->links.khulnasoft_add_to_page_cache_lru_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_add_to_page_cache_lru_kprobe,
                                                                    false, cachestat_fcnt[KHULNASOFT_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU]);
    int ret = libbpf_get_error(obj->links.khulnasoft_add_to_page_cache_lru_kprobe);
    if (ret)
        goto endnakt;

    obj->links.khulnasoft_mark_page_accessed_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_mark_page_accessed_kprobe,
                                                                    false, cachestat_fcnt[KHULNASOFT_KEY_CALLS_MARK_PAGE_ACCESSED]);
    ret = libbpf_get_error(obj->links.khulnasoft_mark_page_accessed_kprobe);
    if (ret)
        goto endnakt;

    if (cachestat_names[0].optional) {
        obj->links.khulnasoft_folio_mark_dirty_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_folio_mark_dirty_kprobe,
                                                                        false, cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
        ret = libbpf_get_error(obj->links.khulnasoft_folio_mark_dirty_kprobe);
        if (ret)
            goto endnakt;

    } else if (cachestat_names[1].optional) {
        obj->links.khulnasoft_set_page_dirty_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_set_page_dirty_kprobe,
                                                                        false, cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
        ret = libbpf_get_error(obj->links.khulnasoft_set_page_dirty_kprobe);
        if (ret)
            goto endnakt;

    } else {
        obj->links.khulnasoft_account_page_dirtied_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_account_page_dirtied_kprobe,
                                                                        false, cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]);
        ret = libbpf_get_error(obj->links.khulnasoft_account_page_dirtied_kprobe);
        if (ret)
            goto endnakt;

    }

    obj->links.khulnasoft_mark_buffer_dirty_kprobe = bpf_program__attach_kprobe(obj->progs.khulnasoft_mark_buffer_dirty_kprobe,
                                                                    false, cachestat_fcnt[KHULNASOFT_KEY_CALLS_MARK_BUFFER_DIRTY]);
    ret = libbpf_get_error(obj->links.khulnasoft_mark_buffer_dirty_kprobe);
    if (ret)
        goto endnakt;

endnakt:
    return ret;
}

static inline int ebpf_load_and_attach(struct cachestat_bpf *obj, int selector)
{
    if (!selector) { //trampoline
        khulnasoft_ebpf_disable_probe(obj);
        khulnasoft_ebpf_disable_specific_trampoline(obj);

        khulnasoft_set_trampoline_target(obj);
    } else { // probe
        khulnasoft_ebpf_disable_trampoline(obj);
        khulnasoft_ebpf_disable_specific_probe(obj);
    } 

    int ret = cachestat_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (!selector)
        ret = cachestat_bpf__attach(obj);
    else
        ret = khulnasoft_attach_kprobe_target(obj);

    if (!ret) {
        fprintf(stdout, "%s: loaded with success\n", (!selector) ? "trampoline" : "probe");
    }

    return ret;
}

static pid_t ebpf_update_tables(int global, int apps)
{
    pid_t pid = getpid();
    uint32_t idx = 0;
    uint64_t value = 1;

    int ret = bpf_map_update_elem(global, &idx, &value, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to global table.");

    khulnasoft_cachestat_t stats = { .add_to_page_cache_lru = 1, .mark_page_accessed = 1,
                                  .account_page_dirtied = 1, .mark_buffer_dirty = 1 };

    idx = (pid_t)pid;
    ret = bpf_map_update_elem(apps, &idx, &stats, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to apps table.");

    return pid;
}

static int cachestat_read_apps_array(int fd, int ebpf_nprocs, uint32_t child)
{
    khulnasoft_cachestat_t stored[ebpf_nprocs];

    uint64_t counter = 0;

    int key, next_key;
    key = next_key = 0;
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
            counter++;
        }
        memset(stored, 0, ebpf_nprocs*sizeof(khulnasoft_cachestat_t));

        key = next_key;
    }

    if (counter) {
        fprintf(stdout, "Apps data stored with success. It collected %lu pids\n", counter);
        return 0;
    }

    return 2;
}


static int ebpf_cachestat_tests(int selector, enum khulnasoft_apps_level map_level)
{
    struct cachestat_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = KHULNASOFT_CORE_PROCESS_NUMBER;

    obj = cachestat_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != KHULNASOFT_MODE_PROBE) {
        cachestat_bpf__destroy(obj);

        obj = cachestat_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = KHULNASOFT_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        int fd = bpf_map__fd(obj->maps.cstat_ctrl);
        ebpf_core_fill_ctrl(obj->maps.cstat_ctrl, map_level);

        fd = bpf_map__fd(obj->maps.cstat_global);
        int fd2 = bpf_map__fd(obj->maps.cstat_pid);
        pid_t my_pid = ebpf_update_tables(fd, fd2);

        sleep(60);
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, KHULNASOFT_CACHESTAT_END);
        if (!ret) {
            ret = cachestat_read_apps_array(fd2, ebpf_nprocs, (uint32_t)my_pid);
            if (ret)
                fprintf(stdout, "Empty apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        fprintf(stderr ,"%s", KHULNASOFT_CORE_DEFAULT_ERROR);
        ret = 3;
    }

    cachestat_bpf__destroy(obj);

    return ret;
load_error:
    fprintf(stderr, "Cannot open or load BPF object\n");
    return 2;
}

static inline void fill_cachestat_fcnt()
{
    ebpf_update_names(cachestat_names);
    int i;
    for (i = 0; cachestat_names[i].program_name ; i++) {
        if (cachestat_names[i].optional) {
            cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED] = cachestat_names[i].optional;
            break;
        }
    }
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
                          ebpf_core_print_help(argv[0], "cachestat", 1, 1);
                          exit(0);
                      }
            case KHULNASOFT_EBPF_CORE_IDX_PROBE: {
                          selector = KHULNASOFT_MODE_PROBE;
                          break;
                      }
            case KHULNASOFT_EBPF_CORE_IDX_TRACEPOINT: {
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
                          selector = KHULNASOFT_MODE_PROBE;
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

    fill_cachestat_fcnt();
    if (!cachestat_fcnt[KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED]) {
        fprintf(stderr, "Cannot find all necessary functions\n");
        return 0;
    }

    struct btf *bf = NULL;
    if (!selector) {
        bf = khulnasoft_parse_btf_file((const char *)KHULNASOFT_BTF_FILE);
        if (bf)
            selector = ebpf_find_functions(bf, selector, cachestat_fcnt, KHULNASOFT_CACHESTAT_END);
    }

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_cachestat_tests(selector, map_level) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }
    return 0;
}

