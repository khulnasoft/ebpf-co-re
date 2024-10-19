#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_shm.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_SHM_END);
} tbl_shm  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, khulnasoft_shm_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_shm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} shm_ctrl SEC(".maps");

/************************************************************************************
 *
 *                     SHARED MEMORY (common)
 *
 ***********************************************************************************/

static __always_inline void khulnasoft_update_stored_data(khulnasoft_shm_t *data, __u32 selector)
{
    // we are using if/else if instead switch to avoid warnings
    if (selector == KHULNASOFT_KEY_SHMGET_CALL)
        libkhulnasoft_update_u32(&data->get, 1);
    else if (selector == KHULNASOFT_KEY_SHMAT_CALL)
        libkhulnasoft_update_u32(&data->at, 1);
    else if (selector == KHULNASOFT_KEY_SHMDT_CALL)
        libkhulnasoft_update_u32(&data->dt, 1);
    else if (selector == KHULNASOFT_KEY_SHMCTL_CALL)
        libkhulnasoft_update_u32(&data->ctl, 1);
}

static __always_inline void khulnasoft_set_structure_value(khulnasoft_shm_t *data, __u32 selector)
{
    // we are using if/else if instead switch to avoid warnings
    if (selector == KHULNASOFT_KEY_SHMGET_CALL)
        data->get = 1;
    else if (selector == KHULNASOFT_KEY_SHMAT_CALL)
        data->at = 1;
    else if (selector == KHULNASOFT_KEY_SHMDT_CALL)
        data->dt = 1;
    else if (selector == KHULNASOFT_KEY_SHMCTL_CALL)
        data->ctl = 1;
}

static __always_inline int khulnasoft_update_apps(__u32 idx)
{
    khulnasoft_shm_t data = {};

    __u32 key = 0;
    __u32 tgid = 0;
    khulnasoft_shm_t *fill = khulnasoft_get_pid_structure(&key, &tgid, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        khulnasoft_update_stored_data(fill, idx);
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);

        khulnasoft_set_structure_value(&data, idx);
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&shm_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_global_apps_shm(__u32 idx)
{
    libkhulnasoft_update_global(&tbl_shm, idx, 1);

    // check if apps is enabled; if not, don't record apps data.
    __u32 key = KHULNASOFT_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl, &key);
    if (apps) {
        if (*apps == 0) {
            return 0;
        }
    }

    return 1;
}

static __always_inline int khulnasoft_ebpf_common_shmget()
{
    int store_apps = khulnasoft_global_apps_shm(KHULNASOFT_KEY_SHMGET_CALL);
    if (!store_apps)
        return 0;

    return khulnasoft_update_apps(KHULNASOFT_KEY_SHMGET_CALL);
}

static __always_inline int khulnasoft_ebpf_common_shmat()
{
    int store_apps = khulnasoft_global_apps_shm(KHULNASOFT_KEY_SHMAT_CALL);
    if (!store_apps)
        return 0;

    return khulnasoft_update_apps(KHULNASOFT_KEY_SHMAT_CALL);
}

static __always_inline int khulnasoft_ebpf_common_shmdt()
{
    int store_apps = khulnasoft_global_apps_shm(KHULNASOFT_KEY_SHMDT_CALL);
    if (!store_apps)
        return 0;

    return khulnasoft_update_apps(KHULNASOFT_KEY_SHMDT_CALL);
}

static __always_inline int khulnasoft_ebpf_common_shmctl()
{
    int store_apps = khulnasoft_global_apps_shm(KHULNASOFT_KEY_SHMCTL_CALL);
    if (!store_apps)
        return 0;

    return khulnasoft_update_apps(KHULNASOFT_KEY_SHMCTL_CALL);
}

/************************************************************************************
 *
 *                     SHARED MEMORY (tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/syscalls/sys_enter_shmget")
int khulnasoft_syscall_shmget(struct trace_event_raw_sys_enter *arg)
{
    return khulnasoft_ebpf_common_shmget();
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int khulnasoft_syscall_shmat(struct trace_event_raw_sys_enter *arg)
{
    return khulnasoft_ebpf_common_shmat();
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int khulnasoft_syscall_shmdt(struct trace_event_raw_sys_enter *arg)
{
    return khulnasoft_ebpf_common_shmdt();
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int khulnasoft_syscall_shmctl(struct trace_event_raw_sys_enter *arg)
{
    return khulnasoft_ebpf_common_shmctl();
}

/************************************************************************************
 *
 *                     SHARED MEMORY (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/khulnasoft_shmget_probe")
int BPF_KPROBE(khulnasoft_shmget_probe)
{
    return khulnasoft_ebpf_common_shmget();
}

SEC("kprobe/khulnasoft_shmat_probe")
int BPF_KPROBE(khulnasoft_shmat_probe)
{
    return khulnasoft_ebpf_common_shmat();
}

SEC("kprobe/khulnasoft_shmdt_probe")
int BPF_KPROBE(khulnasoft_shmdt_probe)
{
    return khulnasoft_ebpf_common_shmdt();
}

SEC("kprobe/khulnasoft_shmctl_probe")
int BPF_KPROBE(khulnasoft_shmctl_probe)
{
    return khulnasoft_ebpf_common_shmctl();
}

/************************************************************************************
 *
 *                     SHARED MEMORY (trampoline)
 *
 ***********************************************************************************/

SEC("fentry/khulnasoft_shmget")
int BPF_PROG(khulnasoft_shmget_fentry)
{
    return khulnasoft_ebpf_common_shmget();
}

SEC("fentry/khulnasoft_shmat")
int BPF_PROG(khulnasoft_shmat_fentry)
{
    return khulnasoft_ebpf_common_shmat();
}

SEC("fentry/khulnasoft_shmdt")
int BPF_PROG(khulnasoft_shmdt_fentry)
{
    return khulnasoft_ebpf_common_shmdt();
}

SEC("fentry/khulnasoft_shmctl")
int BPF_PROG(khulnasoft_shmctl_fentry)
{
    return khulnasoft_ebpf_common_shmctl();
}

char _license[] SEC("license") = "GPL";

