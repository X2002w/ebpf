// io_anomaly.bof.c - io 抖动异常检测 kernel 态

#include "vmlinux.h" 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// cmd_flags mark
#define CMD_FLAGS_MAEK 0xFF

// 每个块设备单独的检测数据

struct dev_stats {
  // 吞吐 and IOPS(每秒输入输出操作次数)
  __u64 rd_count;   // 完成的读请求数
  __u64 wr_count;   // 完成的写请求数
  __u64 rd_bytes;
  __u64 wr_bytes;

  // 延迟
  __u64 total_lat_ns;   // arg latency = total / 采样时间
  __u64 max_lat_ns;
  __u64 lat_samples; 

  // 块设备队列深度
  // insert+, complete-
  __u64 qdepth_cur;   // 当前瞬时值
  __u64 qdepth_max;   // 当前窗口峰值

  // 所属进程？

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
  char rw;          // 读 or 写
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entires, 1);
  __type(key, struct request *);
  __type(valude, io_req_info);
} io_req SEC(".maps");

// block_rq_insert
SEC("raw_tp/block_rq_insert");
int on_block_rq_insert(struct bpf_raw_tracepoint_args *ctx)
{
  struct request *rq = (struct request *)ctx->args[0];
  if(!rq) return 0;

  // 通过rq -> part -> bd_dev直接拿取设备号, 跳两次
  dev_t dev = BPF_READ_CORE(rq, part, bd_dev); 

  // 读取总扇区数: 总字节数 / 512
  unsigned int nr_sector = BPF_READ_CORE(rq, __data_len) >> 9;

  // cmd_flags[24标志位 | 8操作码]
  unsigned int cmd_flags = BPF_READ_CORE(rq, cmd_flags); 
  char rw = ((cmd_flags & CMD_FLAGS_MAEK) == 1) ? 1 : 0;

  struct io_req_info info = {};
  info.insert_ts = bpf_ktime_get_ns();
  info.dev = dev;
  info.nr_sector = nr_sector;
  info.rw = rw;
  bpf_map_update_elem(&io_req, &rq, &info, BPF_ANY);

  struct dev_stats *s = bpf_map_lookup_elem(&dev_stats, &dev);
  if (!s) {
    struct dev_stats zero = {};
    bpf_map_update_elem(&dev_stats, &dev, &zero, BPF_ANY);
    s = bpf_map_lookup_elem(&dev_stats, &dev);
    if (!s) return 0;
  }

  if (s) {
    __sync_fetch_and_add(&s->qdepth_cur, 1);
    if (s->qdepth_cur > s->qdepth_max)
      s->qdepth_max = s->qdepth_cur;
  }

  return 0;
}


// block_rq_complete
// vmlinux -> 113658
SEC("tp/block/blocke_rq_complete");
int on_block_rq_complete(struct trace_event_raw_block_rq_completion *ctx)
{
  // 查找设备号
  dev_t dev = ctx->dev;
  struct dev_stats *s = bpf_map_lookup_elem(&dev_stats, &dev);

  // 第一次出现, 添加到map中
  if (!s)
  {
    struct dev_stats zero = {};
    bpf_map_update_elem(&dev_stats, &dev, &zero, BPF_ANY);
    s = bpf_map_lookup_elem(&dev_stats, &dev);
    if (!s) return 0;
  }
  
  // 计算字节数 = 扇区数 * 区块字节数
  __u64 bytes = (__u64)ctx->nr_sector * 512;
  
  // read or write
  if (ctx->rwbs[0] == 'R')
  {
    __sync_fetch_and_add(&s->rd_count, 1);
    __sync_fetch_and_add(&s->rd_bytes, bytes);
  }
  else if (ctx->rwbs[0] == 'W')
  {
    __sync_fetch_and_add(&s->wr_count, 1);
    __sync_fetch_and_add(&s->wr_bytes, bytes);
  }

}



