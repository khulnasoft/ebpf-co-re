#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_process.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct khulnasoft_pid_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_GLOBAL_COUNTER);
} tbl_total_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} process_ctrl SEC(".maps");

/************************************************************************************
 *
 *                              COMMON SECTION 
 *
 ***********************************************************************************/

static __always_inline void khulnasoft_fill_common_process_data(struct khulnasoft_pid_stat_t *data)
{
    data->ct = bpf_ktime_get_ns();
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    __u32 pid = (0xFFFFFFFF00000000 & pid_tgid)>>32;

    data->tgid = tgid;
    data->pid = pid;
}

static __always_inline int khulnasoft_process_not_update_apps()
{
    __u32 key = KHULNASOFT_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&process_ctrl ,&key);
    if (apps && *apps)
        return 0;

    return 1;
}


static __always_inline int khulnasoft_common_release_task()
{
    struct khulnasoft_pid_stat_t *fill;
    __u32 key = 0;
    __u32 tgid = 0;

    libkhulnasoft_update_global(&tbl_total_stats, KHULNASOFT_KEY_CALLS_RELEASE_TASK, 1);
    if (khulnasoft_process_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &process_ctrl, &tbl_pid_stats);
    if (fill) {
        libkhulnasoft_update_u32(&fill->release_call, 1) ;

        libkhulnasoft_update_global(&process_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_DEL, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_fork_clone(int ret)
{
    __u32 key = 0;
    __u32 tgid = 0;
    struct khulnasoft_pid_stat_t data = { };
    struct khulnasoft_pid_stat_t *fill;

    if (ret < 0) {
        libkhulnasoft_update_global(&tbl_total_stats, KHULNASOFT_KEY_ERROR_PROCESS, 1);
    } 

    if (khulnasoft_process_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &process_ctrl, &tbl_pid_stats);
    if (fill) {
        fill->release_call = 0;

        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->task_err, 1) ;
        } 
    } else {
        khulnasoft_fill_common_process_data(&data);
        data.tgid = tgid;
        if (ret < 0) {
            data.task_err = 1;
        } 
        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&process_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

/************************************************************************************
 *
 *                     PROCESS SECTION (tracepoints)
 *
 ***********************************************************************************/

// It must be always enabled
SEC("tracepoint/sched/sched_process_exit")
int khulnasoft_tracepoint_sched_process_exit(struct khulnasoft_sched_process_exit *ptr)
{
    struct khulnasoft_pid_stat_t *fill;
    __u32 key = 0;
    __u32 tgid = 0;

    libkhulnasoft_update_global(&tbl_total_stats, KHULNASOFT_KEY_CALLS_DO_EXIT, 1);
    if (khulnasoft_process_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &process_ctrl, &tbl_pid_stats);
    if (fill) {
        libkhulnasoft_update_u32(&fill->exit_call, 1) ;
    } 

    return 0;
}

// It must be always enabled
SEC("tracepoint/sched/sched_process_exec")
int khulnasoft_tracepoint_sched_process_exec(struct khulnasoft_sched_process_exec *ptr)
{
    struct khulnasoft_pid_stat_t data = { };
    struct khulnasoft_pid_stat_t *fill;
    __u32 key = 0;
    __u32 tgid = 0;
    // This is necessary, because it represents the main function to start a thread
    libkhulnasoft_update_global(&tbl_total_stats, KHULNASOFT_KEY_CALLS_PROCESS, 1);

    libkhulnasoft_update_global(&tbl_total_stats, KHULNASOFT_KEY_CALLS_DO_EXIT, 1);
    if (khulnasoft_process_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &process_ctrl, &tbl_pid_stats);
    if (fill) {
        fill->release_call = 0;
        libkhulnasoft_update_u32(&fill->create_process, 1) ;
    } else {
        khulnasoft_fill_common_process_data(&data);
        data.tgid = tgid;
        data.create_process = 1;

        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&process_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

// It must be always enabled
SEC("tracepoint/sched/sched_process_fork")
int khulnasoft_tracepoint_sched_process_fork(struct khulnasoft_sched_process_fork *ptr)
{
    struct khulnasoft_pid_stat_t data = { };
    struct khulnasoft_pid_stat_t *fill;
    __u32 key = 0;
    __u32 tgid = 0;

    libkhulnasoft_update_global(&tbl_total_stats, KHULNASOFT_KEY_CALLS_PROCESS, 1);

    // Parent ID = 1 means that init called process/thread creation
    int thread = 0;
    if (ptr->parent_pid != ptr->child_pid && ptr->parent_pid != 1) {
        thread = 1;
        libkhulnasoft_update_global(&tbl_total_stats, KHULNASOFT_KEY_CALLS_THREAD, 1);
    }

    if (khulnasoft_process_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &process_ctrl, &tbl_pid_stats);
    if (fill) {
        fill->release_call = 0;
        libkhulnasoft_update_u32(&fill->create_process, 1);
        if (thread)
            libkhulnasoft_update_u32(&fill->create_thread, 1);
    } else {
        khulnasoft_fill_common_process_data(&data);
        data.tgid = tgid;
        data.create_process = 1;
        if (thread)
            data.create_thread = 1;

        bpf_map_update_elem(&tbl_pid_stats, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&process_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int khulnasoft_clone_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return khulnasoft_common_fork_clone(ret);
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int khulnasoft_clone3_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return khulnasoft_common_fork_clone(ret);
}

SEC("tracepoint/syscalls/sys_exit_fork")
int khulnasoft_fork_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return khulnasoft_common_fork_clone(ret);
}

SEC("tracepoint/syscalls/sys_exit_vfork")
int khulnasoft_vfork_exit(struct trace_event_raw_sys_exit *ctx)
{
    int ret = (int)ctx->ret;
    return khulnasoft_common_fork_clone(ret);
}

/************************************************************************************
 *
 *                     PROCESS SECTION (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/release_task")
int BPF_KPROBE(khulnasoft_release_task_probe)
{
    return khulnasoft_common_release_task();
}

// Must be disabled on user ring when kernel is newer than 5.9.16
SEC("kretprobe/_do_fork")
int BPF_KPROBE(khulnasoft_do_fork_probe)
{
    int ret = (int)PT_REGS_RC(ctx);
    return khulnasoft_common_fork_clone(ret);
}

// Must be disabled on user ring when kernel is older than 5.10.0
SEC("kretprobe/kernel_clone")
int BPF_KPROBE(khulnasoft_kernel_clone_probe)
{
    int ret = (int)PT_REGS_RC(ctx);
    return khulnasoft_common_fork_clone(ret);
}

/************************************************************************************
 *
 *                     PROCESS SECTION (trampoline)
 *
 ***********************************************************************************/

SEC("fentry/release_task")
int BPF_PROG(khulnasoft_release_task_fentry)
{
    return khulnasoft_common_release_task();
}

SEC("fexit/khulnasoft_clone_fexit")
int BPF_PROG(khulnasoft_clone_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);

    return khulnasoft_common_fork_clone(ret);
}

SEC("fexit/khulnasoft_clone3_fexit")
int BPF_PROG(khulnasoft_clone3_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);

    return khulnasoft_common_fork_clone(ret);
}

char _license[] SEC("license") = "GPL";

