#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_fd.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct khulnasoft_fd_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_fd_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_FD_COUNTER);
} tbl_fd_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} fd_ctrl SEC(".maps");

/************************************************************************************
 *
 *                           COMMON SECTION
 *
 ***********************************************************************************/

static __always_inline int khulnasoft_are_apps_enabled()
{
    __u32 key = KHULNASOFT_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&fd_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    return 1;
}

/************************************************************************************
 *
 *                           KPROBE SECTION
 *
 ***********************************************************************************/
static __always_inline int khulnasoft_apps_do_sys_openat2(long ret)
{
    struct khulnasoft_fd_stat_t *fill;
    struct khulnasoft_fd_stat_t data = { };

    if (!khulnasoft_are_apps_enabled())
        return 0;

    __u32 key = 0;
    __u32 tgid = 0;
    fill = khulnasoft_get_pid_structure(&key, &tgid, &fd_ctrl, &tbl_fd_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->open_call, 1) ;
        if (ret < 0) 
            libkhulnasoft_update_u32(&fill->open_err, 1) ;
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        data.open_call = 1;
        if (ret < 0)
            data.open_err = 1;

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&fd_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }


    return 0;
}

static __always_inline void khulnasoft_sys_open_global(long ret)
{
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_ERROR_DO_SYS_OPEN, 1);

    libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_CALLS_DO_SYS_OPEN, 1);
}

static __always_inline int khulnasoft_apps_close_fd(int ret)
{
    struct khulnasoft_fd_stat_t data = { };
    struct khulnasoft_fd_stat_t *fill;

    if (!khulnasoft_are_apps_enabled())
        return 0;

    __u32 key = 0;
    __u32 tgid = 0;
    fill = khulnasoft_get_pid_structure(&key, &tgid, &fd_ctrl, &tbl_fd_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->close_call, 1) ;
        if (ret < 0)
            libkhulnasoft_update_u32(&fill->close_err, 1) ;
    } else {
        data.ct = bpf_ktime_get_ns();
        data.tgid = tgid;
        libkhulnasoft_update_uid_gid(&data.uid, &data.gid);
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
        data.close_call = 1;
        if (ret < 0)
            data.close_err = 1;

        bpf_map_update_elem(&tbl_fd_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&fd_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline void khulnasoft_close_global(int ret)
{
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_ERROR_CLOSE_FD, 1);

    libkhulnasoft_update_global(&tbl_fd_global, KHULNASOFT_KEY_CALLS_CLOSE_FD, 1);
}

/************************************************************************************
 *
 *                           FD SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(khulnasoft_sys_open_kretprobe)
{
    long ret = (long)PT_REGS_RC(ctx);
    khulnasoft_sys_open_global(ret);

    return khulnasoft_apps_do_sys_openat2(ret);
}

SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(khulnasoft_sys_open_kprobe)
{
    khulnasoft_sys_open_global(0);

    return khulnasoft_apps_do_sys_openat2(0);
}

SEC("kretprobe/close_fd")
int BPF_KRETPROBE(khulnasoft_close_fd_kretprobe)
{
    int ret = (ssize_t)PT_REGS_RC(ctx);
    khulnasoft_close_global(ret);

    return khulnasoft_apps_close_fd(ret);
}

SEC("kprobe/close_fd")
int BPF_KPROBE(khulnasoft_close_fd_kprobe)
{
    khulnasoft_close_global(0);

    return khulnasoft_apps_close_fd(0);
}

SEC("kretprobe/__close_fd")
int BPF_KRETPROBE(khulnasoft___close_fd_kretprobe)
{
    int ret = (ssize_t)PT_REGS_RC(ctx);
    khulnasoft_close_global(ret);

    return khulnasoft_apps_close_fd(ret);
}

SEC("kprobe/__close_fd")
int BPF_KPROBE(khulnasoft___close_fd_kprobe)
{
    khulnasoft_close_global(0);

    return khulnasoft_apps_close_fd(0);
}

/************************************************************************************
 *
 *                           FD SECTION(trampoline)
 *
 ***********************************************************************************/

SEC("fexit/do_sys_openat2")
int BPF_PROG(khulnasoft_sys_open_fexit, int dfd, const char *filename, struct open_how *how, long ret)
{
    khulnasoft_sys_open_global(ret);

    return khulnasoft_apps_do_sys_openat2(ret);
}

SEC("fentry/do_sys_openat2")
int BPF_PROG(khulnasoft_sys_open_fentry)
{
    khulnasoft_sys_open_global(0);

    return khulnasoft_apps_do_sys_openat2(0);
}

SEC("fentry/close_fd")
int BPF_PROG(khulnasoft_close_fd_fentry)
{
    khulnasoft_close_global(0);

    return khulnasoft_apps_close_fd(0);
}

SEC("fexit/close_fd")
int BPF_PROG(khulnasoft_close_fd_fexit, unsigned fd, int ret)
{
    khulnasoft_close_global(ret);

    return khulnasoft_apps_close_fd(ret);
}

SEC("fentry/__close_fd")
int BPF_PROG(khulnasoft___close_fd_fentry)
{
    khulnasoft_close_global(0);

    return khulnasoft_apps_close_fd(0);
}

SEC("fexit/__close_fd")
int BPF_PROG(khulnasoft___close_fd_fexit, struct files_struct *files, unsigned fd, int ret)
{
    khulnasoft_close_global(ret);

    return khulnasoft_apps_close_fd(ret);
}

char _license[] SEC("license") = "GPL";

