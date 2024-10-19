#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_dc.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_DIRECTORY_CACHE_END);
} dcstat_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, khulnasoft_dc_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} dcstat_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} dcstat_ctrl SEC(".maps");

/***********************************************************************************
 *
 *                               DC COMMON
 *
 ***********************************************************************************/

static __always_inline int khulnasoft_dc_not_update_apps()
{
    __u32 key = KHULNASOFT_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&key);
    if (apps && *apps)
        return 0;

    return 1;
}

static __always_inline int khulnasoft_common_lookup_fast()
{
    khulnasoft_dc_stat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    libkhulnasoft_update_global(&dcstat_global, KHULNASOFT_KEY_DC_REFERENCE, 1);

    if (khulnasoft_dc_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->references, 1);
    } else {
        data.references = 1;
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&dcstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_d_lookup(long ret)
{
    khulnasoft_dc_stat_t *fill, data = {};
    __u32 key = 0;
    __u32 tgid = 0;

    libkhulnasoft_update_global(&dcstat_global, KHULNASOFT_KEY_DC_SLOW, 1);

    if (khulnasoft_dc_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->slow, 1);
    } else {
        data.slow = 1;
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&dcstat_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    // file not found
    if (!ret) {
        libkhulnasoft_update_global(&dcstat_global, KHULNASOFT_KEY_DC_MISS, 1);
        fill = khulnasoft_get_pid_structure(&key, &tgid, &dcstat_ctrl, &dcstat_pid);
        if (fill) {
            libkhulnasoft_update_u32(&fill->missed, 1);
        }
    }

    return 0;
}

/***********************************************************************************
 *
 *                            DC SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/lookup_fast")
int BPF_KPROBE(khulnasoft_lookup_fast_kprobe)
{
    return khulnasoft_common_lookup_fast();
}

SEC("kretprobe/d_lookup")
int BPF_KRETPROBE(khulnasoft_d_lookup_kretprobe)
{
    long ret = PT_REGS_RC(ctx);

    return khulnasoft_common_d_lookup(ret);
}

/***********************************************************************************
 *
 *                            DC SECTION(trampoline)
 *
 ***********************************************************************************/

SEC("fentry/lookup_fast")
int BPF_PROG(khulnasoft_lookup_fast_fentry)
{
    return khulnasoft_common_lookup_fast();
}

SEC("fexit/d_lookup")
int BPF_PROG(khulnasoft_d_lookup_fexit, const struct dentry *parent, const struct qstr *name, 
             struct dentry *ret)
{
    return khulnasoft_common_d_lookup((long)ret);
}

char _license[] SEC("license") = "GPL";

