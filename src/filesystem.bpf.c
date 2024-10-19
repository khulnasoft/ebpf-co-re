#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_fs.h"

/************************************************************************************
 *     
 *                                 MAP Section
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_FS_MAX_ELEMENTS);
} tbl_fs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} fs_ctrl SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,  4192);
} tmp_fs SEC(".maps");


/************************************************************************************
 *     
 *                                 COMMON
 *     
 ***********************************************************************************/

static __always_inline int khulnasoft_fs_entry()
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_fs, &pid, &ts, BPF_ANY);

    libkhulnasoft_update_global(&fs_ctrl, KHULNASOFT_CONTROLLER_TEMP_TABLE_ADD, 1);

    return 0;
}

static __always_inline int khulnasoft_fs_store_bin(__u32 selection)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 bin, pid = (__u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tmp_fs, &pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_fs, &pid);

    libkhulnasoft_update_global(&fs_ctrl, KHULNASOFT_CONTROLLER_TEMP_TABLE_DEL, 1);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;
    bin = libkhulnasoft_select_idx(data, KHULNASOFT_FS_MAX_BINS_POS);
    __u32 idx = selection * KHULNASOFT_FS_MAX_BINS + bin;
    if (idx >= KHULNASOFT_FS_MAX_ELEMENTS)
        return 0;

    fill = bpf_map_lookup_elem(&tbl_fs, &idx);
    if (fill) {
        libkhulnasoft_update_u64(fill, 1);
		return 0;
    } 

    data = 1;
    bpf_map_update_elem(&tbl_fs, &idx, &data, BPF_ANY);

    return 0;
}

/************************************************************************************
 *     
 *                                 ENTRY SECTION (trampoline)
 *     
 ***********************************************************************************/

SEC("fentry/fs_file_read")
int BPF_PROG(khulnasoft_fs_file_read_entry, struct kiocb *iocb) 
{
    struct file *fp = iocb->ki_filp;
    if (!fp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("fentry/fs_file_write")
int BPF_PROG(khulnasoft_fs_file_write_entry, struct kiocb *iocb) 
{
    struct file *fp = iocb->ki_filp;
    if (!fp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("fentry/fs_file_open")
int BPF_PROG(khulnasoft_fs_file_open_entry, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("fentry/fs_2nd_file_open")
int BPF_PROG(khulnasoft_fs_2nd_file_open_entry, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("fentry/fs_getattr")
int BPF_PROG(khulnasoft_fs_getattr_entry) 
{
    return khulnasoft_fs_entry();
}

/************************************************************************************
 *     
 *                                 END SECTION (trampoline)
 *     
 ***********************************************************************************/

SEC("fexit/fs_file_read")
int BPF_PROG(khulnasoft_fs_file_read_exit)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_READ);
}

SEC("fexit/fs_file_write")
int BPF_PROG(khulnasoft_fs_file_write_exit)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_WRITE);
}

SEC("fexit/fs_file_open")
int BPF_PROG(khulnasoft_fs_file_open_exit)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_OPEN);
}

SEC("fexit/fs_2nd_file_open")
int BPF_PROG(khulnasoft_fs_2nd_file_open_exit)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_OPEN);
}

SEC("fexit/fs_getattr")
int BPF_PROG(khulnasoft_fs_getattr_exit)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_SYNC);
}

/************************************************************************************
 *     
 *                                 ENTRY SECTION (kprobe)
 *     
 ***********************************************************************************/

SEC("kprobe/fs_file_read")
int BPF_KPROBE(khulnasoft_fs_file_read_probe, struct kiocb *iocb) 
{
    struct file *fp = BPF_CORE_READ(iocb, ki_filp);
    if (!fp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("kprobe/fs_file_write")
int BPF_KPROBE(khulnasoft_fs_file_write_probe, struct kiocb *iocb) 
{
    struct file *fp = BPF_CORE_READ(iocb, ki_filp);
    if (!fp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("kprobe/fs_file_open")
int BPF_KPROBE(khulnasoft_fs_file_open_probe, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("kprobe/fs_2nd_file_open")
int BPF_KPROBE(khulnasoft_fs_2nd_file_open_probe, struct inode *inode, struct file *filp) 
{
    if (!filp)
        return 0;

    return khulnasoft_fs_entry();
}

SEC("kprobe/fs_getattr")
int BPF_KPROBE(khulnasoft_fs_getattr_probe) 
{
    return khulnasoft_fs_entry();
}

/************************************************************************************
 *     
 *                                 END SECTION (kretprobe)
 *     
 ***********************************************************************************/

SEC("kretprobe/fs_file_read")
int BPF_KRETPROBE(khulnasoft_fs_file_read_retprobe)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_READ);
}

SEC("kretprobe/fs_file_write")
int BPF_KRETPROBE(khulnasoft_fs_file_write_retprobe)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_WRITE);
}

SEC("kretprobe/fs_file_open")
int BPF_KRETPROBE(khulnasoft_fs_file_open_retprobe)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_OPEN);
}

SEC("kretprobe/fs_2nd_file_open")
int BPF_KRETPROBE(khulnasoft_fs_2nd_file_open_retprobe)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_OPEN);
}

SEC("kretprobe/fs_getattr")
int BPF_KRETPROBE(khulnasoft_fs_getattr_retprobe)
{
    return khulnasoft_fs_store_bin(KHULNASOFT_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";


