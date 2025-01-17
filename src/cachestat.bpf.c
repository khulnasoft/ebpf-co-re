#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_cache.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CACHESTAT_END);
} cstat_global  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, khulnasoft_cachestat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} cstat_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} cstat_ctrl SEC(".maps");

/************************************************************************************
 *
 *                             CACHESTAT Common
 *
 ***********************************************************************************/

static __always_inline int khulnasoft_cachetat_not_update_apps(__u32 idx)
{
    libkhulnasoft_update_global(&cstat_global, idx, 1);

    __u32 key = KHULNASOFT_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&cstat_ctrl ,&key);
    if (apps && *apps)
        return 0;

    return 1;
}

static __always_inline int khulnasoft_common_page_cache_lru()
{
    khulnasoft_cachestat_t *fill, data = {};

    if (khulnasoft_cachetat_not_update_apps(KHULNASOFT_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU))
        return 0;

    __u32 key = 0;
    __u32 tgid = 0;
    fill = khulnasoft_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->add_to_page_cache_lru, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        data.tgid = tgid;
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        
        data.add_to_page_cache_lru = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&cstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_page_accessed()
{
    khulnasoft_cachestat_t *fill, data = {};
    if (khulnasoft_cachetat_not_update_apps(KHULNASOFT_KEY_CALLS_MARK_PAGE_ACCESSED))
        return 0;

    __u32 key = 0;
    __u32 tgid = 0;
    fill = khulnasoft_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->mark_page_accessed, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        
        data.mark_page_accessed = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&cstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_page_dirtied()
{
    khulnasoft_cachestat_t *fill, data = {};

    if (khulnasoft_cachetat_not_update_apps(KHULNASOFT_KEY_CALLS_ACCOUNT_PAGE_DIRTIED))
        return 0;

    __u32 key = 0;
    __u32 tgid = 0;
    fill = khulnasoft_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->account_page_dirtied, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        
        data.account_page_dirtied = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&cstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_buffer_dirty()
{
    khulnasoft_cachestat_t *fill, data = {};

    if (khulnasoft_cachetat_not_update_apps(KHULNASOFT_KEY_CALLS_MARK_BUFFER_DIRTY))
        return 0;

    __u32 key = 0;
    __u32 tgid = 0;
    fill = khulnasoft_get_pid_structure(&key, &tgid, &cstat_ctrl, &cstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->mark_buffer_dirty, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        
        data.mark_buffer_dirty = 1;
        bpf_map_update_elem(&cstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&cstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

/************************************************************************************
 *
 *                             CACHESTAT Section (Probe)
 *
 ***********************************************************************************/

SEC("kprobe/add_to_page_cache_lru")
int BPF_KPROBE(khulnasoft_add_to_page_cache_lru_kprobe)
{
    return khulnasoft_common_page_cache_lru();
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(khulnasoft_mark_page_accessed_kprobe)
{
    return khulnasoft_common_page_accessed();
}

// When kernel 5.16.0 was released the function __set_page_dirty became static
// and a new function was created.
SEC("kprobe/__folio_mark_dirty")
int BPF_KPROBE(khulnasoft_folio_mark_dirty_kprobe)
{
    return khulnasoft_common_page_dirtied();
}

// When kernel 5.15.0 was released the function account_page_dirtied became static
// https://elixir.bootlin.com/linux/v5.15/source/mm/page-writeback.c#L2441
// as consequence of this, we are monitoring the function from caller.
SEC("kprobe/__set_page_dirty")
int BPF_KPROBE(khulnasoft_set_page_dirty_kprobe)
{
    struct page *page = (struct page *)PT_REGS_PARM1(ctx) ;
    struct address_space *mapping =  _(page->mapping);

    if (!mapping)
        return 0;

    return khulnasoft_common_page_dirtied();
}

SEC("kprobe/account_page_dirtied")
int BPF_KPROBE(khulnasoft_account_page_dirtied_kprobe)
{
    return khulnasoft_common_page_dirtied();
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(khulnasoft_mark_buffer_dirty_kprobe)
{
    return khulnasoft_common_buffer_dirty();
}

/************************************************************************************
 *
 *                             CACHESTAT Section (Probe)
 *
 ***********************************************************************************/

SEC("fentry/add_to_page_cache_lru")
int BPF_PROG(khulnasoft_add_to_page_cache_lru_fentry)
{
    return khulnasoft_common_page_cache_lru();
}

SEC("fentry/mark_page_accessed")
int BPF_PROG(khulnasoft_mark_page_accessed_fentry)
{
    return khulnasoft_common_page_accessed();
}

// When kernel 5.16.0 was released the function __set_page_dirty became static
// and a new function was created.
SEC("fentry/__folio_mark_dirty")
int BPF_PROG(khulnasoft_folio_mark_dirty_fentry)
{
    return khulnasoft_common_page_dirtied();
}

// When kernel 5.15.0 was released the function account_page_dirtied became static
// https://elixir.bootlin.com/linux/v5.15/source/mm/page-writeback.c#L2441
// as consequence of this, we are monitoring the function from caller.
SEC("fentry/__set_page_dirty")
int BPF_PROG(khulnasoft_set_page_dirty_fentry, struct page *page)
{
    if (!page->mapping)
        return 0;

    return khulnasoft_common_page_dirtied();
}

SEC("fentry/account_page_dirtied")
int BPF_PROG(khulnasoft_account_page_dirtied_fentry)
{
    return khulnasoft_common_page_dirtied();
}

SEC("fentry/mark_buffer_dirty")
int BPF_PROG(khulnasoft_mark_buffer_dirty_fentry)
{
    return khulnasoft_common_buffer_dirty();
}

char _license[] SEC("license") = "GPL";

