#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_mount.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_MOUNT_END);
} tbl_mount SEC(".maps");

/************************************************************************************
 *
 *                     MOUNT SECTION (tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/syscalls/sys_exit_mount")
int khulnasoft_mount_exit(struct trace_event_raw_sys_exit *arg)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_CALL, 1);

    int ret = (int)arg->ret;
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_ERROR, 1);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_umount")
int khulnasoft_umount_exit(struct trace_event_raw_sys_exit *arg)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_CALL, 1);

    int ret = (int)arg->ret;
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_ERROR, 1);

    return 0;
}

/************************************************************************************
 *
 *                     MOUNT SECTION (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/khulnasoft_mount_probe")
int BPF_KPROBE(khulnasoft_mount_probe)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_CALL, 1);

    return 0;
}

SEC("kretprobe/khulnasoft_mount_retprobe")
int BPF_KRETPROBE(khulnasoft_mount_retprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_ERROR, 1);

    return 0;
}

SEC("kprobe/khulnasoft_umount_probe")
int BPF_KPROBE(khulnasoft_umount_probe)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_CALL, 1);

    return 0;
}

SEC("kretprobe/khulnasoft_umount_retprobe")
int BPF_KRETPROBE(khulnasoft_umount_retprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_ERROR, 1);

    return 0;
}

/************************************************************************************
 *
 *                     MOUNT SECTION (trampoline)
 *
 ***********************************************************************************/

SEC("fentry/khulnasoft_mount")
int BPF_PROG(khulnasoft_mount_fentry)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_CALL, 1);

    return 0;
}

SEC("fexit/khulnasoft_mount")
int BPF_PROG(khulnasoft_mount_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_MOUNT_ERROR, 1);

    return 0;
}

SEC("fentry/khulnasoft_umount")
int BPF_PROG(khulnasoft_umount_fentry)
{
    libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_CALL, 1);

    return 0;
}

SEC("fexit/khulnasoft_umount")
int BPF_PROG(khulnasoft_umount_fexit, const struct pt_regs *regs)
{
    int ret = (int)PT_REGS_RC(regs);
    if (ret < 0)
        libkhulnasoft_update_global(&tbl_mount, KHULNASOFT_KEY_UMOUNT_ERROR, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";

