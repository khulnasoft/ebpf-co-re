#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "khulnasoft_core.h"
#include "khulnasoft_vfs.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct khulnasoft_vfs_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_vfs_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_VFS_COUNTER);
} tbl_vfs_stats  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, KHULNASOFT_CONTROLLER_END);
} vfs_ctrl SEC(".maps");

/************************************************************************************
 *
 *                                Local Function Section
 *
 ***********************************************************************************/

static __always_inline void khulnasoft_fill_common_vfs_data(struct khulnasoft_vfs_stat_t *data)
{
    data->ct = bpf_ktime_get_ns();
    libkhulnasoft_update_uid_gid(&data->uid, &data->gid);
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);
}

static __always_inline int khulnasoft_vfs_not_update_apps()
{
    __u32 key = KHULNASOFT_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&vfs_ctrl ,&key);
    if (apps && *apps)
        return 0;

    return 1;
}


/************************************************************************************
 *     
 *                               VFS Common
 *     
 ***********************************************************************************/

static __always_inline int khulnasoft_common_vfs_write(__u64 tot, ssize_t ret)
{
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_WRITE, 1);

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_WRITE, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->write_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->write_err, 1) ;
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_WRITE, 1);
        } else
            libkhulnasoft_update_u64(&fill->write_bytes, tot);

    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0)
            data.write_err = 1;
        else
            data.write_bytes = tot;

        data.write_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_vfs_writev(__u64 tot, ssize_t ret)
{
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_WRITEV, 1);

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_WRITEV, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->writev_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->writev_err, 1) ;
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_WRITEV, 1);
        } else {
            libkhulnasoft_update_u64(&fill->writev_bytes, tot);
        }
    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0) {
            data.writev_err = 1;
        } else {
            data.writev_bytes = (unsigned long)tot;
        }
        data.writev_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_vfs_read(__u64 tot, ssize_t ret)
{
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_READ, 1);
    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_READ, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->read_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->read_err, 1) ;
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_READ, 1);
        } else {
            libkhulnasoft_update_u64(&fill->read_bytes, tot);
        }
    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0) {
            data.read_err = 1;
        } else {
            data.read_bytes = (unsigned long)tot;
        }
        data.read_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_vfs_readv(__u64 tot, ssize_t ret)
{
    struct khulnasoft_vfs_stat_t *fill;
    struct khulnasoft_vfs_stat_t data = { };

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_READV, 1);
    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_BYTES_VFS_READV, tot);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->readv_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_READV, 1);
            libkhulnasoft_update_u32(&fill->readv_err, 1) ;
        } else {
            libkhulnasoft_update_u64(&fill->readv_bytes, tot);
        }
    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0) {
            data.readv_err = 1;
        } else {
            data.readv_bytes = (unsigned long)tot;
        }
        data.readv_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_vfs_unlink(int ret)
{
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_UNLINK, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->unlink_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_UNLINK, 1);
            libkhulnasoft_update_u32(&fill->unlink_err, 1) ;
        }
    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0)
            data.unlink_err = 1;
        else 
            data.unlink_err = 0;
        data.unlink_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_vfs_fsync(int ret)
{
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_FSYNC, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->fsync_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->fsync_err, 1) ;
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_FSYNC, 1);
        } 
    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0) {
            data.fsync_err = 1;
        } else {
            data.fsync_err = 0;
        }
        data.fsync_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_vfs_open(int ret)
{
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_OPEN, 1);
    
    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->open_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->open_err, 1) ;
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_OPEN, 1);
        } 
    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0) {
            data.open_err = 1;
        } else {
            data.open_err = 0;
        }
        data.open_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int khulnasoft_common_vfs_create(int ret)
{
    struct khulnasoft_vfs_stat_t data = { };
    struct khulnasoft_vfs_stat_t *fill;

    libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_CALLS_VFS_CREATE, 1);

    __u32 key = 0;
    __u32 tgid = 0;
    if (khulnasoft_vfs_not_update_apps())
        return 0;

    fill = khulnasoft_get_pid_structure(&key, &tgid, &vfs_ctrl, &tbl_vfs_pid);
    if (fill) {
        libkhulnasoft_update_u32(&fill->create_call, 1) ;

        if (ret < 0) {
            libkhulnasoft_update_u32(&fill->create_err, 1) ;
            libkhulnasoft_update_global(&tbl_vfs_stats, KHULNASOFT_KEY_ERROR_VFS_CREATE, 1);
        } 
    } else {
        khulnasoft_fill_common_vfs_data(&data);
        data.tgid = tgid;

        if (ret < 0) {
            data.create_err = 1;
        } else {
            data.create_err = 0;
        }
        data.create_call = 1;

        bpf_map_update_elem(&tbl_vfs_pid, &key, &data, BPF_ANY);

        libkhulnasoft_update_global(&vfs_ctrl, KHULNASOFT_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

/************************************************************************************
 *     
 *                            VFS Section (kprobe)
 *     
 ***********************************************************************************/

SEC("kprobe/vfs_write")
int BPF_KPROBE(khulnasoft_vfs_write_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    return khulnasoft_common_vfs_write(tot, 0);
}

SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(khulnasoft_vfs_write_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_write(tot, ret);
}

SEC("kprobe/vfs_writev")
int BPF_KPROBE(khulnasoft_vfs_writev_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    return khulnasoft_common_vfs_writev(tot, 0);
}

SEC("kretprobe/vfs_writev")
int BPF_KRETPROBE(khulnasoft_vfs_writev_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_writev(tot, ret);
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(khulnasoft_vfs_read_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    return khulnasoft_common_vfs_read(tot, 0);
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(khulnasoft_vfs_read_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_read(tot, ret);
}

SEC("kprobe/vfs_readv")
int BPF_KPROBE(khulnasoft_vfs_readv_kprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    return khulnasoft_common_vfs_readv(tot, 0);
}

SEC("kretprobe/vfs_readv")
int BPF_KRETPROBE(khulnasoft_vfs_readv_kretprobe)
{
    ssize_t ret = (ssize_t)PT_REGS_PARM3(ctx);
    __u64 tot = libkhulnasoft_log2l(ret);

    ret = (ssize_t)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_readv(tot, ret);
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(khulnasoft_vfs_unlink_kprobe)
{
    return khulnasoft_common_vfs_unlink(0);
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(khulnasoft_vfs_unlink_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_unlink(ret);
}

SEC("kprobe/vfs_fsync")
int BPF_KPROBE(khulnasoft_vfs_fsync_kprobe)
{
    return khulnasoft_common_vfs_fsync(0);
}

SEC("kretprobe/vfs_fsync")
int BPF_KRETPROBE(khulnasoft_vfs_fsync_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_fsync(ret);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(khulnasoft_vfs_open_kprobe)
{
    return khulnasoft_common_vfs_open(0);
}

SEC("kretprobe/vfs_open")
int BPF_KRETPROBE(khulnasoft_vfs_open_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_open(ret);
}

SEC("kprobe/vfs_create")
int BPF_KPROBE(khulnasoft_vfs_create_kprobe)
{
    return khulnasoft_common_vfs_create(0);
}

SEC("kretprobe/vfs_create")
int BPF_KRETPROBE(khulnasoft_vfs_create_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    return khulnasoft_common_vfs_create(ret);
}

/************************************************************************************
 *     
 *                            VFS Section (trampoline)
 *     
 ***********************************************************************************/

SEC("fentry/vfs_write")
int BPF_PROG(khulnasoft_vfs_write_fentry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    __u64 tot = libkhulnasoft_log2l((ssize_t)count);

    return khulnasoft_common_vfs_write(tot, 0);
}

SEC("fexit/vfs_write")
int BPF_PROG(khulnasoft_vfs_write_fexit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libkhulnasoft_log2l(ret);
    else
        tot = 0;

    return khulnasoft_common_vfs_write(tot, ret);
}

SEC("fentry/vfs_writev")
int BPF_PROG(khulnasoft_vfs_writev_fentry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    __u64 tot = libkhulnasoft_log2l((ssize_t)count);

    return khulnasoft_common_vfs_writev(tot, 0);
}

SEC("fexit/vfs_writev")
int BPF_PROG(khulnasoft_vfs_writev_fexit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libkhulnasoft_log2l(ret);
    else
        tot = 0;

    return khulnasoft_common_vfs_writev(tot, ret);
}

SEC("fentry/vfs_read")
int BPF_PROG(khulnasoft_vfs_read_fentry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    __u64 tot = libkhulnasoft_log2l((ssize_t)count);

    return khulnasoft_common_vfs_read(tot, 0);
}

SEC("fexit/vfs_read")
int BPF_PROG(khulnasoft_vfs_read_fexit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libkhulnasoft_log2l(ret);
    else
        tot = 0;

    return khulnasoft_common_vfs_read(tot, ret);
}

SEC("fentry/vfs_readv")
int BPF_PROG(khulnasoft_vfs_readv_fentry, struct file *file, const struct iovec *vec, unsigned long vlen, loff_t *pos, rwf_t flags)
{
    __u64 tot = libkhulnasoft_log2l((ssize_t) vlen);

    return khulnasoft_common_vfs_readv(tot, 0);
}

SEC("fexit/vfs_readv")
int BPF_PROG(khulnasoft_vfs_readv_fexit, struct file *file, const struct iovec *vec, unsigned long vlen, loff_t *pos, rwf_t flags,
             ssize_t ret)
{
    __u64 tot;
    if (ret > 0)
        tot = libkhulnasoft_log2l(ret);
    else
        tot = 0;

    return khulnasoft_common_vfs_readv(tot, ret);
}

SEC("fentry/vfs_unlink")
int BPF_PROG(khulnasoft_vfs_unlink_fentry)
{
    return khulnasoft_common_vfs_unlink(0);
}

/*
SEC("fexit/vfs_unlink")
// KERNEL NEWER THAN 5.11.22
int BPF_PROG(khulnasoft_vfs_unlink_fexit, struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry,
             struct inode **delegated_inode, int ret)
// KERNEL OLDER THAN 5.12.0             
int BPF_PROG(khulnasoft_vfs_unlink_fexit,struct inode *dir, struct dentry *dentry, struct inode **delegated_inode, int ret)
{
    return khulnasoft_common_vfs_unlink(ret);
}
*/

SEC("fentry/vfs_fsync")
int BPF_PROG(khulnasoft_vfs_fsync_fentry)
{
    return khulnasoft_common_vfs_fsync(0);
}

SEC("fexit/vfs_fsync")
int BPF_PROG(khulnasoft_vfs_fsync_fexit, struct file *file, int datasync, int ret)
{
    return khulnasoft_common_vfs_fsync(ret);
}

SEC("fentry/vfs_open")
int BPF_PROG(khulnasoft_vfs_open_fentry)
{
    return khulnasoft_common_vfs_open(0);
}

SEC("fexit/vfs_open")
int BPF_PROG(khulnasoft_vfs_open_fexit, const struct path *path, struct file *file, int ret)
{
    return khulnasoft_common_vfs_open(ret);
}

SEC("fentry/vfs_create")
int BPF_PROG(khulnasoft_vfs_create_fentry)
{
    return khulnasoft_common_vfs_create(0);
}

/*
SEC("fexit/vfs_create")
// KERNEL NEWER THAN 5.11.22
int BPF_PROG(khulnasoft_vfs_create_fexit, struct user_namespace *mnt_userns, struct inode *dir,
             struct dentry *dentry, umode_t mode, bool want_excl, int ret)
// KERNEL OLDER THAN 5.12.0             
int BPF_PROG(khulnasoft_vfs_create_fexit, struct inode *dir, struct dentry *dentry, umode_t mode,
	     bool want_excl, int ret)
{
    return khulnasoft_common_vfs_create(ret);
}
*/

char _license[] SEC("license") = "GPL";

