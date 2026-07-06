// hotfile.bpf.c 热点文件访问追踪

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


#define TASK_COMM_LEN 16
#define FNAME_LEN 40

// 每个inod的 IO统计
struct file_io_stat {
  __u64 rd_count;
  __u64 wr_count;
  __u64 rd_bytes;
  __u64 wr_bytes;
  __u64 total_lat_ns; // 此文件在采样时间内的vfs 层读写延迟累计


  __u64 last_ts;      // 最近一次访问时间

  char comm[TASK_COMM_LEN];
  char fname[FNAME_LEN];
};

 // file_stat map  
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);
  __type(value, struct file_io_stat);
} file_stats SEC(".maps");

// 存储在读写某个文件时, 进入vfs_read/write的时间, 用于计算延迟
struct vfs_pending_key {
  __u32 tid;
  __u32 __pad;  // 对齐
  __u64 file_addr;
};

struct vfs_pending_val {
  __u64 ts;
  __u64 file_key;  // key
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct vfs_pending_key);
  __type(value, struct vfs_pending_val);
} vfs_pending SEC(".maps");


// 从 vmlinux里的struct file结构体提取dev+inode 组合key
static inline __u64 get_file_key(struct file *f)
{
  unsigned long ino = BPF_CORE_READ(f, f_inode, i_ino);
  dev_t dev = BPF_CORE_READ(f, f_inode, i_sb, s_dev);
  return ((__u64)dev << 32) | ino;
}

// 获取文件名
static inline void get_fname(struct file *f, char *buf, int len)
{
  const unsigned char *name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
  bpf_probe_read_kernel_str(buf, len, name);
}

static inline struct file_io_stat* get_or_create_file_stat(__u64 file_key, struct file *file)
{
  struct file_io_stat *s = bpf_map_lookup_elem(&file_stats, &file_key);
  if (s)  return s;

  struct file_io_stat zero = {};
  bpf_map_update_elem(&file_stats, &file_key, &zero, BPF_ANY);
  s = bpf_map_lookup_elem(&file_stats, &file_key);
  if (s && s->comm[0] == 0) {
    bpf_get_current_comm(s->comm, TASK_COMM_LEN);
    get_fname(file, s->fname, FNAME_LEN);
  }
  return s;
}
  
// vfs 记录读写开始时间
// 参数列表从linux 源码fs/read_read.c的定义里获取
SEC("fentry/vfs_read")
int BPF_PROG(vfs_read_entry, struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  // 获取触发当前epbf事件的进程id/线程id
  struct vfs_pending_key key = {
    .tid = (__u32)bpf_get_current_pid_tgid(),
    .file_addr = (__u64)file,
  };
  struct vfs_pending_val val = {
    .ts = bpf_ktime_get_ns(),
    .file_key = get_file_key(file),
  };
  bpf_map_update_elem(&vfs_pending, &key, &val, BPF_ANY);
  return 0;
}

SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, struct file *file, char __user *buf, size_t count, loff_t *pos, ssize_t ret)
{
  if (ret <= 0)
    return 0;

  struct vfs_pending_key key = {
    .tid = (__u32)bpf_get_current_pid_tgid(),
    .file_addr = (__u64)file,
  };
  struct vfs_pending_val *val = bpf_map_lookup_elem(&vfs_pending, &key);
  if (!val)
    return 0;

  // 计算一次读文件vfa层耗时
  __u64 lat_ns = bpf_ktime_get_ns() - val->ts;

  // 获取文件 io读写信息
  struct file_io_stat *s = get_or_create_file_stat(val->file_key, file);
  if (s) {
    __sync_fetch_and_add(&s->rd_count, 1);
    __sync_fetch_and_add(&s->rd_bytes, (__u64)ret);
    __sync_fetch_and_add(&s->total_lat_ns, lat_ns);
    s->last_ts = bpf_ktime_get_ns();
  }
  bpf_map_delete_elem(&vfs_pending, &key);
  return 0;
}

SEC("fentry/vfs_write")
int BPF_PROG(vfs_write_entry, struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
  // 获取触发当前epbf事件的进程id/线程id
  struct vfs_pending_key key = {
    .tid = (__u32)bpf_get_current_pid_tgid(),
    .file_addr = (__u64)file,
  };
  struct vfs_pending_val val = {
    .ts = bpf_ktime_get_ns(),
    .file_key = get_file_key(file),
  };
  bpf_map_update_elem(&vfs_pending, &key, &val, BPF_ANY);
  return 0;
}


SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit, struct file *file, const char __user *buf, size_t count, loff_t *pos, ssize_t ret)
{
  if (ret <= 0)
    return 0;

  struct vfs_pending_key key = {
    .tid = (__u32)bpf_get_current_pid_tgid(),
    .file_addr = (__u64)file,
  };
  struct vfs_pending_val *val = bpf_map_lookup_elem(&vfs_pending, &key);
  if (!val)
    return 0;

  // 计算一次读文件vfa层耗时
  __u64 lat_ns = bpf_ktime_get_ns() - val->ts;

  // 获取文件 io读写信息
  struct file_io_stat *s = get_or_create_file_stat(val->file_key, file);
  if (s) {
    __sync_fetch_and_add(&s->wr_count, 1);
    __sync_fetch_and_add(&s->wr_bytes, (__u64)ret);
    __sync_fetch_and_add(&s->total_lat_ns, lat_ns);
    s->last_ts = bpf_ktime_get_ns();
  }
  bpf_map_delete_elem(&vfs_pending, &key);
  return 0;
}


