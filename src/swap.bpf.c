#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_swap.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_SWAP_END);
} tbl_swap  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, khulnasoft_swap_access_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_swap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} swap_ctrl SEC(".maps");

/***********************************************************************************
 *
 *                               SWAP COMMON
 *
 ***********************************************************************************/

static __always_inline int khulnasoft_swap_not_update_apps()
{
    __u32 key = KHULNASOFT_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&swap_ctrl ,&key);
    if (apps && *apps)
        return 0;

    return 1;
}

static __always_inline int common_readpage()
{
    khulnasoft_swap_access_t data = {};

    libkhulnasoft_update_global(&tbl_swap, KHULNASOFT_KEY_SWAP_READPAGE_CALL, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_swap_not_update_apps())
        return 0;

    khulnasoft_swap_access_t *fill = khulnasoft_get_pid_structure(&key, &tgid, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libkhulnasoft_update_u32(&fill->read, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        data.read = 1;

        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&swap_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int common_writepage()
{
    khulnasoft_swap_access_t data = {};

    libkhulnasoft_update_global(&tbl_swap, KHULNASOFT_KEY_SWAP_WRITEPAGE_CALL, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_swap_not_update_apps())
        return 0;

    khulnasoft_swap_access_t *fill = khulnasoft_get_pid_structure(&key, &tgid, &swap_ctrl, &tbl_pid_swap);
    if (fill) {
        libkhulnasoft_update_u32(&fill->write, 1);
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        data.write = 1;

        bpf_map_update_elem(&tbl_pid_swap, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&swap_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

/***********************************************************************************
 *
 *                            SWAP SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/swap_read_folio")
int BPF_KPROBE(khulnasoft_swap_read_folio_probe)
{
    return common_readpage();
}

SEC("kprobe/swap_readpage")
int BPF_KPROBE(khulnasoft_swap_readpage_probe)
{
    return common_readpage();
}

SEC("kprobe/swap_writepage")
int BPF_KPROBE(khulnasoft_swap_writepage_probe)
{
    return common_writepage();
}

/***********************************************************************************
 *
 *                            SWAP SECTION(trampoline)
 *
 ***********************************************************************************/

SEC("fentry/swap_read_folio")
int BPF_PROG(khulnasoft_swap_read_folio_fentry)
{
    return common_readpage();
}

SEC("fentry/swap_readpage")
int BPF_PROG(khulnasoft_swap_readpage_fentry)
{
    return common_readpage();
}

SEC("fentry/swap_writepage")
int BPF_PROG(khulnasoft_swap_writepage_fentry)
{
    return common_writepage();
}

char _license[] SEC("license") = "GPL";

