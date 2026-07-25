// io_anomaly.bpf.c - io 抖动异常检测 kernel 态

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/bpf_shared.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// cmd_flags mark
#define CMD_FLAGS_MARK 0xFF
#define CACHE_WINDOW_NS 500000000ULL  // 500ms 同块重复读判定窗口

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u32);
  __type(value, struct dev_stats);

} dev_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct block_read_key);
  __type(value, struct block_read_val);
} block_read_hist SEC(".maps");

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
  __u8 rw = ((cmd_flags & CMD_FLAGS_MARK) == 1) ? 1 : 0;

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

  // 缓存失效检测: 仅读请求，检测同块短时间内重复读
  if (rw == 0 && s) {

    // 读取当前扇区
    __u64 sector = BPF_CORE_READ(rq, __sector);
    struct block_read_key bk = { 
      .dev = dev,
      .sector = sector
    };
    struct block_read_val *bv = bpf_map_lookup_elem(&block_read_hist, &bk);
    __u64 now = bpf_ktime_get_ns();

    __sync_fetch_and_add(&s->total_rd_blks, 1);

    if (bv && (now - bv->last_ts) < CACHE_WINDOW_NS) {
      __sync_fetch_and_add(&s->cache_miss_count, 1);
      __sync_fetch_and_add(&s->cache_miss_bytes, (__u64)nr_sector * 512);
      bv->last_ts = now;
      __sync_fetch_and_add(&bv->read_count, 1);
    } 
    else {
      struct block_read_val new_val = {
        .first_ts = now,
        .last_ts = now,
        .read_count = 1,
      };
      bpf_map_update_elem(&block_read_hist, &bk, &new_val, BPF_ANY);
    }
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

