// io_anomaly.bpf.c - io 抖动异常检测 kernel 态

#include "vmlinux.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// cmd_flags mark
#define CMD_FLAGS_MAEK 0xFF
#define HIST_SLOTS 16

// 每个块设备单独的检测数据

struct dev_stats {
  // 吞吐 and IOPS(每秒输入输出操作次数)
  __u64 rd_count;   // 完成的读请求数
  __u64 wr_count;   // 完成的写请求数
  __u64 rd_bytes;
  __u64 wr_bytes;

  // 延迟
  __u64 total_lat_ns;   // arg latency = total / 采样时间
  __u64 total_qwait_ns;
  __u64 total_svc_ns;
  __u64 max_lat_ns;

  // 块设备队列深度
  // 分为insert->issue, issue->complete两个阶段
  __u64 ii_qdepth_cur;
  __u64 ic_qdepth_cur;

  __u64 ii_qdepth_max;
  __u64 ic_qdepth_max;

  // 延迟直方图: bucket [i] = [2^i, 2^(i+1)) us, bucket 0 = [0, 2) us
  __u64 lat_hist[HIST_SLOTS];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, struct dev_stats);

} dev_stats SEC(".maps");

// 单次IO_request
struct io_req_info {
  __u64 insert_ts;  // io_insert 时间戳
  __u64 issue_ts;   
  dev_t dev;        // dev设备号
  unsigned int  nr_sector;    // 读写扇区数量
  __u8 rw;          // 读 or 写
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct request *);
  __type(value, struct io_req_info);
} io_req SEC(".maps");


// 获取设备号: 优先 rq->part->bd_dev，fallback rq->q->disk->major/first_minor
// BPF_CORE_READ 在指针为 NULL 时返回 0，两条路径互为兜底
static inline dev_t get_rq_dev(struct request *rq)
{
  dev_t dev = BPF_CORE_READ(rq, part, bd_dev);
  if (dev)
    return dev;

  int major = BPF_CORE_READ(rq, q, disk, major);
  int first_minor = BPF_CORE_READ(rq, q, disk, first_minor);
  return ((major & 0xFFFFF) << 20) | (first_minor & 0xFFFFF);
}

// 获取struct dev_stats
static inline struct dev_stats *get_dev_stats(dev_t dev)
{
  struct dev_stats *s = bpf_map_lookup_elem(&dev_stats, &dev);
  if (!s) {
    struct dev_stats zero = {};
    bpf_map_update_elem(&dev_stats, &dev, &zero, BPF_ANY);
    s = bpf_map_lookup_elem(&dev_stats, &dev);
    if (!s) return 0;
  }
  return s;
}



// 延迟分桶: power-of-2 us, 共 HIST_SLOTS 桶
static inline __u32 lat_to_slot(__u64 lat_ns)
{
  __u64 lat_us = lat_ns / 1000;
  if (lat_us < 2)
    return 0;
  __u32 slot = 64 - __builtin_clzll(lat_us) - 1;
  if (slot >= HIST_SLOTS)
    slot = HIST_SLOTS - 1;
  return slot;
}

// block_rq_insert
SEC("raw_tp/block_rq_insert")
int on_block_rq_insert(struct bpf_raw_tracepoint_args *ctx)
{
  struct request *rq = (struct request *)ctx->args[0];
  if(!rq) return 0;

  dev_t dev = get_rq_dev(rq); 

  // 读取总扇区数: 总字节数 / 512
  unsigned int nr_sector = BPF_CORE_READ(rq, __data_len) >> 9;

  // cmd_flags[24标志位 | 8操作码]
  unsigned int cmd_flags = BPF_CORE_READ(rq, cmd_flags); 
  __u8 rw = ((cmd_flags & CMD_FLAGS_MAEK) == 1) ? 1 : 0;

  struct io_req_info info = {};
  info.insert_ts = bpf_ktime_get_ns();
  info.dev = dev;
  info.nr_sector = nr_sector;
  info.rw = rw;
  bpf_map_update_elem(&io_req, &rq, &info, BPF_ANY);

  struct dev_stats *s = get_dev_stats(dev);
  if (s) {
    __sync_fetch_and_add(&s->ii_qdepth_cur, 1);
    if (s->ii_qdepth_cur > s->ii_qdepth_max)
      s->ii_qdepth_max = s->ii_qdepth_cur;
  }

  return 0;
}

// block_rq_issue
SEC("raw_tp/block_rq_issue")
int on_block_rq_issue(struct bpf_raw_tracepoint_args *ctx) 
{
  struct request *rq = (struct request *)ctx->args[0];
  if (!rq) return 0;

  struct io_req_info *info = bpf_map_lookup_elem(&io_req, &rq);
  if (!info) return 0;

  info->issue_ts = bpf_ktime_get_ns();

  struct dev_stats *s = get_dev_stats(info->dev);
  if (s) {
    if (s->ii_qdepth_cur > 0)
      __sync_fetch_and_sub(&s->ii_qdepth_cur, 1);

    __sync_fetch_and_add(&s->ic_qdepth_cur, 1);
    if (s->ic_qdepth_cur > s->ic_qdepth_max)
      s->ic_qdepth_max = s->ic_qdepth_cur;
  }
  return 0;
}

// block_rq_complete
SEC("raw_tp/block_rq_complete")
int on_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) 
{
  struct request *rq = (struct request *)ctx->args[0];
  if (!rq) return 0;

  struct io_req_info *info = bpf_map_lookup_elem(&io_req, &rq);
  if (!info) return 0;

  __u64 now = bpf_ktime_get_ns();
  __u64 total_lat = now - info->insert_ts;
  __u64 qwait = 0;
  __u64 svc = total_lat;
  if (info->issue_ts > 0 && info->issue_ts >= info->insert_ts) {
    qwait = info->issue_ts - info->insert_ts;
    svc = now - info->issue_ts;
  }

  __u64 bytes = (__u64)info->nr_sector * 512;

  struct dev_stats *s = get_dev_stats(info->dev);
  if (s) {
    if(info->rw) {
      __sync_fetch_and_add(&s->wr_count, 1);
      __sync_fetch_and_add(&s->wr_bytes, bytes);
    }
    else {
      __sync_fetch_and_add(&s->rd_count, 1);
      __sync_fetch_and_add(&s->rd_bytes, bytes);
    }

    __sync_fetch_and_add(&s->total_lat_ns, total_lat);
    __sync_fetch_and_add(&s->total_qwait_ns, qwait);
    __sync_fetch_and_add(&s->total_svc_ns, svc);

    if (total_lat > s->max_lat_ns)
      s->max_lat_ns = total_lat;

    __u32 slot = lat_to_slot(total_lat);
    if (slot < HIST_SLOTS)
      __sync_fetch_and_add(&s->lat_hist[slot], 1);

    if (s->ic_qdepth_cur > 0)
      __sync_fetch_and_sub(&s->ic_qdepth_cur, 1);
  }

  // 一次io请求完成后，清除当前条目
  bpf_map_delete_elem(&io_req, &rq);

  return 0;
}

