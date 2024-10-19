#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_sync.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_SYNC_END);
} tbl_sync SEC(".maps");

/************************************************************************************
 *
 *                               SYNC SECTION (trampoline and kprobe)
 *
 ***********************************************************************************/

SEC("fentry/khulnasoft_sync")
int BPF_PROG(khulnasoft_sync_fentry)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("kprobe/khulnasoft_sync")
int BPF_KPROBE(khulnasoft_sync_kprobe)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int khulnasoft_syncfs_entry(struct trace_event_raw_sys_enter *ctx)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msync")
int khulnasoft_msync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int khulnasoft_sync_file_range_entry(struct trace_event_raw_sys_enter *ctx)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int khulnasoft_fsync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int khulnasoft_fdatasync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int khulnasoft_sync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libkhulnasoft_update_global(&tbl_sync, KHULNASOFT_KEY_SYNC_CALL, 1);

    return 0;
}


char _license[] SEC("license") = "GPL";

