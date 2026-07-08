// io_anomaly.c — I/O 异常检测用户态程序
// 加载 BPF skeleton，周期性读取 dev_stats map，打印设备 I/O 统计

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "io_anomaly.skel.h"
#include "hotfile.skel.h"

#define DEFAULT_INTERVAL 3
#define MAX_ACTIVE_DEVS 256
#define MAX_THRASH_ENTRIES 5

// 与 BPF 侧 struct dev_stats 保持一致的统计结构
struct dev_stats {
	unsigned long long rd_count;
	unsigned long long wr_count;
	unsigned long long rd_bytes;
	unsigned long long wr_bytes;
	unsigned long long total_lat_ns;
	unsigned long long total_qwait_ns;
	unsigned long long total_svc_ns;
	unsigned long long max_lat_ns;
  unsigned long long ii_qdepth_cur;
  unsigned long long ic_qdepth_cur;
  unsigned long long ii_qdepth_max;
  unsigned long long ic_qdepth_max;
  unsigned long long lat_hist[16];
  unsigned long long cache_miss_count;
  unsigned long long cache_miss_bytes;
  unsigned long long total_rd_blks;
};

struct block_read_key {
  unsigned int dev;
  unsigned long long sector;
};

struct block_read_val {
  unsigned long long first_ts;
  unsigned long long last_ts;
  unsigned int read_count;
};

struct file_io_stat {
  unsigned long long rd_count;
  unsigned long long wr_count;
  unsigned long long rd_bytes;
  unsigned long long wr_bytes;
  unsigned long long total_lat_ns;
  unsigned long long last_ts;
  char comm[16];
  char fname[40];
}; 

// 热点文件
struct hot_entry {
  unsigned long long file_key;
  struct file_io_stat stat;
};

struct thrash_entry {
	unsigned int dev;
	unsigned long long sector;
	unsigned int read_count;
};

static volatile sig_atomic_t exiting;

static void on_signal(int sig) { (void)sig; exiting = 1; }

static void iso_timestamp(char *buf, size_t len)
{
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}


// 读取 /proc/partitions 获取当前活跃块设备列表，转为 dev_t 数组
static int get_active_devs(__u32 *devs, int max_devs)
{
	FILE *f = fopen("/proc/partitions", "r");
	if (!f) return 0;

	char line[256];
	int count = 0;

	fgets(line, sizeof(line), f); // 跳过表头
	fgets(line, sizeof(line), f); // 跳过空行

	while (fgets(line, sizeof(line), f) && count < max_devs) {
		unsigned int maj, min;
		char name[64];
		if (sscanf(line, "%u %u %*u %63s", &maj, &min, name) == 3)
			devs[count++] = (maj << 20) | (min & 0xFFFFF);
	}
	fclose(f);
	return count;
}

// 检查 dev_t 是否在活跃设备列表中
static int dev_is_active(__u32 dev, const __u32 *devs, int count)
{
	for (int i = 0; i < count; i++)
		if (devs[i] == dev) return 1;
	return 0;
}

// 从 histogram 计算 Pxx 延迟 (us), bucket [i] = [2^i, 2^(i+1)) us, bucket 0 = [0, 2) us
static double calc_percentile(const unsigned long long *hist, int slots,
                               unsigned long long total, double pct)
{
	if (total == 0) return 0;
	unsigned long long target = (unsigned long long)((double)total * pct);
	if (target == 0) target = 1;

	unsigned long long accum = 0;
	for (int i = 0; i < slots; i++) {
		accum += hist[i];
		if (accum >= target) {
			// 上界作为保守估计
			if (i == 0) return 2.0;
			return (double)(1ULL << (i + 1));
		}
	}
	return (double)(1ULL << slots);
}

static int cmp_thrash(const void *a, const void *b)
{
	const struct thrash_entry *ta = (const struct thrash_entry *)a;
	const struct thrash_entry *tb = (const struct thrash_entry *)b;
	if (ta->read_count < tb->read_count) return 1;
	if (ta->read_count > tb->read_count) return -1;
	return 0;
}

static void print_cache_thrash_report(FILE *out, int block_hist_fd)
{
	struct thrash_entry top[MAX_THRASH_ENTRIES];
	int nr = 0;

	struct block_read_key key = {}, next_key;
	while (bpf_map_get_next_key(block_hist_fd, &key, &next_key) == 0) {
		struct block_read_val val = {};
		if (bpf_map_lookup_elem(block_hist_fd, &next_key, &val) != 0) {
			key = next_key;
			continue;
		}

		if (val.read_count < 2) {
			key = next_key;
			continue;
		}

		if (nr < MAX_THRASH_ENTRIES) {
			top[nr].dev = next_key.dev;
			top[nr].sector = next_key.sector;
			top[nr].read_count = val.read_count;
			nr++;
			qsort(top, nr, sizeof(top[0]), cmp_thrash);
		} 
    else if (val.read_count > top[MAX_THRASH_ENTRIES - 1].read_count) {
			top[MAX_THRASH_ENTRIES - 1].dev = next_key.dev;
			top[MAX_THRASH_ENTRIES - 1].sector = next_key.sector;
			top[MAX_THRASH_ENTRIES - 1].read_count = val.read_count;
			qsort(top, nr, sizeof(top[0]), cmp_thrash);
		}

		key = next_key;
	}

	if (nr == 0) return;

	fprintf(out,
		"──────────────────────────────────────────────────────────────────────\n"
		"  缓存颠簸热点 Top-%d (窗口内同扇区重复读次数)\n"
		"──────────────────────────────────────────────────────────────────────\n\n",
		nr);

	for (int i = 0; i < nr; i++) {
		unsigned int maj = top[i].dev >> 20;
		unsigned int min = top[i].dev & 0xFFFFF;
		fprintf(out,
			"  [%d] dev=%u:%u  sector=%llu  重复读次数: %u\n",
			i + 1, maj, min,
			(unsigned long long)top[i].sector,
			top[i].read_count);
	}
	fprintf(out, "\n");
}

static void reset_block_read_hist(int map_fd)
{
	struct block_read_key key = {}, next_key;
	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_delete_elem(map_fd, &next_key);
		key = next_key;
	}
}

static void print_io_report(FILE *out, int stats_fd, int req_fd, double interval_s)
{
	char ts[32];
	iso_timestamp(ts, sizeof(ts));

	fprintf(out,
		"======================================================================\n"
		"  I/O 异常观测 — 设备统计报告\n"
		"======================================================================\n"
		"  时间窗口: %s  (采样间隔 %.1fs)\n"
		"----------------------------------------------------------------------\n\n",
		ts, interval_s);

	__u32 active_devs[MAX_ACTIVE_DEVS];
	int active_count = get_active_devs(active_devs, MAX_ACTIVE_DEVS);

	__u32 key = 0, next_key;
	int seq = 0;
	int has_data = 0;

	while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
		struct dev_stats val = {};
		if (bpf_map_lookup_elem(stats_fd, &next_key, &val) != 0) {
			key = next_key;
			continue;
		}

		// 清理已移除设备留下的僵尸条目
		if (!dev_is_active(next_key, active_devs, active_count)) {
			bpf_map_delete_elem(stats_fd, &next_key);
			key = next_key;
			continue;
		}

		if (val.rd_count == 0 && val.wr_count == 0) {
			key = next_key;
			continue;
		}

		has_data = 1;
		seq++;

		__u32 dev = next_key;
		// 内核 dev_t 为 32 位: major=bits[20:31], minor=bits[0:19]
		unsigned int maj = dev >> 20;
		unsigned int min = dev & 0xFFFFF;

		unsigned long long total_ios = val.rd_count + val.wr_count;
		double iops = (double)total_ios / interval_s;
		double rd_mbps = (double)val.rd_bytes / interval_s / 1e6;
		double wr_mbps = (double)val.wr_bytes / interval_s / 1e6;
		double avg_lat_us = total_ios > 0
			? (double)val.total_lat_ns / (double)total_ios / 1000.0 : 0;
		double avg_qwait_us = total_ios > 0
			? (double)val.total_qwait_ns / (double)total_ios / 1000.0 : 0;
		double avg_svc_us = total_ios > 0
			? (double)val.total_svc_ns / (double)total_ios / 1000.0 : 0;
		double max_lat_us = (double)val.max_lat_ns / 1000.0;
		double p99_us = calc_percentile(val.lat_hist, 16, total_ios, 0.99);
		double p999_us = calc_percentile(val.lat_hist, 16, total_ios, 0.999);

		// 缓存命中率估算
		unsigned long long total_blks = val.total_rd_blks;
		unsigned long long miss = val.cache_miss_count;
		double miss_rate = total_blks > 0
			? (double)miss / (double)total_blks * 100.0 : 0;
		double hit_rate = 100.0 - miss_rate;
		char cache_anomaly[128] = "";
		if (total_blks > 100 && miss_rate > 10.0)
			snprintf(cache_anomaly, sizeof(cache_anomaly),
				"  !! 缓存失效率过高 (%.1f%%) — 页面缓存可能严重不足", miss_rate);

    // 读取内核支持的最大io处理积压深度
    int kernel_dqpth_max = 0;
    FILE *f = fopen("/sys/block/sda/queue/nr_requests", "r");
    if (f)
      fscanf(f, "%d", &kernel_dqpth_max);
    fclose(f);

		fprintf(out,
			"──────────────────────────────────────────────────────────────────────\n"
			"  [%d] 设备 %u:%u  (dev=%u)\n"
			"──────────────────────────────────────────────────────────────────────\n\n"
			"  吞吐与 IOPS:\n"
			"    读请求:  %llu 次  |  %.2f MB/s\n"
			"    写请求:  %llu 次  |  %.2f MB/s\n"
			"    总 IOPS: %.0f\n\n"
			"  延迟:\n"
			"    平均总延迟:   %7.1f us\n"
			"    平均排队等待: %7.1f us\n"
			"    平均服务时间: %7.1f us\n"
			"    最大延迟:     %7.1f us\n"
			"    P99 延迟:     %7.1f us\n"
			"    P99.9 延迟:   %7.1f us\n\n"
			"  io请求队列深度:\n"
			"    当前瞬时值: %llu\n"
			"    窗口峰值:   %llu\n\n"
      "  io处理积压队列深度:\n"
      "    当前瞬时值: %llu\n"
      "    窗口峰值:   %llu\n"
      "  当前内核支持的最大积压队列深度: %d\n\n"
      "  缓存命中率估算:\n"
      "    读块总数:     %llu\n"
      "    重复读块数:   %llu  (缓存失效)\n"
      "    重复读字节:   %.1f MB\n"
      "    估算命中率:   %.1f%%\n"
      "    %s\n",
			seq, maj, min, dev,
			val.rd_count, rd_mbps,
			val.wr_count, wr_mbps,
			iops,
			avg_lat_us, avg_qwait_us, avg_svc_us, max_lat_us, p99_us, p999_us,
			val.ii_qdepth_cur, val.ii_qdepth_max,
      val.ic_qdepth_cur, val.ic_qdepth_max,
      kernel_dqpth_max,
      total_blks,
      miss,
      (double)val.cache_miss_bytes / 1e6,
      hit_rate,
      cache_anomaly);


		key = next_key;
	}

	if (!has_data)
		fprintf(out, "  (未采集到 I/O 数据 — 请确认系统有磁盘活动)\n\n");

	// 显示残留的 in-flight 请求数（调试用）
  // bio 存在合并, 此处有大量条目处于泄露状态
	int in_flight = 0;
	__u64 rkey = 0, rnext;
	while (bpf_map_get_next_key(req_fd, &rkey, &rnext) == 0) {
		in_flight++;
		rkey = rnext;
	}
	if (in_flight > 0)
		fprintf(out, "  当前 in-flight I/O 请求: %d\n\n", in_flight);

	fprintf(out, "======================================================================\n\n");
	fflush(out);
}

static void reset_dev_stats(int map_fd)
{
	__u32 key = 0, next_key;
	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		bpf_map_delete_elem(map_fd, &next_key);
		key = next_key;
	}
}

static int cmp_hot_by_iops(const void *a, const void *b)
{
  const struct hot_entry *ha = (const struct hot_entry *)a;
  const struct hot_entry *hb = (const struct hot_entry *)b;
  unsigned long long ia = ha->stat.rd_count + ha->stat.wr_count;
  unsigned long long ib = hb->stat.rd_count + hb->stat.wr_count;
  if (ia < ib) return 1;
  if (ia > ib) return -1;
  return 0;
}

static void print_hotfile_report(FILE *out, int file_stats_fd, double interval_s)
{
  // 1. 遍历 file_stats, 收集到一个数组中
  struct hot_entry entries[10240];
  int nr = 0;
  unsigned long long total_ios = 0;

  __u64 key = 0, next_key;
  while (bpf_map_get_next_key(file_stats_fd, &key, &next_key) == 0
         && nr < 10240) {
    struct file_io_stat val = {};
    if (bpf_map_lookup_elem(file_stats_fd, &next_key, &val) == 0) {
        entries[nr].file_key = next_key;
        entries[nr].stat     = val;
        total_ios += val.rd_count + val.wr_count;
        nr++;
    }
    key = next_key;
  }

  if (nr == 0) {
    fprintf(out, "  (未采集到文件级 I/O 数据)\n\n");
    return;
  }

  // 2. 按 IOPS 降序排列
  qsort(entries, nr, sizeof(entries[0]), cmp_hot_by_iops);

  // 3. 打印 top-10 热点文件
  fprintf(out,
      "──────────────────────────────────────────────────────────────────────\n"
      "  热点文件访问 Top-10\n"
      "──────────────────────────────────────────────────────────────────────\n\n");

  unsigned long long top3_ios = 0;
  for (int i = 0; i < nr && i < 10; i++) {
    __u32 dev = (__u32)(entries[i].file_key >> 32);
    __u64 inode = entries[i].file_key & 0xFFFFFFFFULL;
    struct file_io_stat *s = &entries[i].stat;

    unsigned long long ios  = s->rd_count + s->wr_count;
    double iops = (double)ios / interval_s;
    double rd_mbps = (double)s->rd_bytes / interval_s / 1e6;
    double wr_mbps = (double)s->wr_bytes / interval_s / 1e6;
    double avg_lat_us = ios > 0
        ? (double)s->total_lat_ns / (double)ios / 1000.0 : 0;

    fprintf(out,
        "  [%d] dev=%u:%u ino=%lu  %s (comm=%s)\n"
        "      IOPS: %.0f  |  读: %.1f MB/s  |  写: %.1f MB/s  |  平均延迟: %.1f us\n\n",
        i + 1, dev >> 20, dev & 0xFFFFF, (unsigned long)inode,
        s->fname[0] ? s->fname : "(unknown)",
        s->comm[0]  ? s->comm  : "(unknown)",
        iops, rd_mbps, wr_mbps, avg_lat_us);

    if (i < 3) top3_ios += ios;
  }

  // 4. 集中度判定
  if (total_ios > 0) {
    double top3_pct = (double)top3_ios / (double)total_ios * 100.0;
    fprintf(out, "  文件访问集中度:\n");
    fprintf(out, "    Top-3 文件 IOPS 占比: %.1f%%\n", top3_pct);

    if (top3_pct > 70.0)
      fprintf(out, "    >> 热点文件访问集中 — Top-3 文件占总 I/O %.1f%%\n", top3_pct);
    else if (top3_pct > 50.0)
      fprintf(out, "    >> 存在一定热点集中 — Top-3 文件占总 I/O %.1f%%\n", top3_pct);
    else
      fprintf(out, "    文件访问分布均匀, 无明显热点\n");
}

  fprintf(out, "\n");
}

static void reset_file_stats(int map_fd)
{
  __u64 key = 0, next_key;
  while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
    bpf_map_delete_elem(map_fd, &next_key);
    key = next_key;
  }
}

// I/O 诊断 

enum { DIOK_NVME, DIOK_SSD, DIOK_HDD, DIOK_UNKNOWN };

static int get_disk_kind(__u32 dev)
{
  unsigned int maj = dev >> 20;
  unsigned int min = dev & 0xFFFFF;
  char path[128];

  // 分区设备没有 queue/rotational，fallback 到父设备
  snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/queue/rotational", maj, min);
  FILE *f = fopen(path, "r");
  if (!f) {
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/../queue/rotational", maj, min);
    f = fopen(path, "r");
  }
  int rot = 1;
  if (f) {
    fscanf(f, "%d", &rot);
    fclose(f);
  }

  // 检查是否 NVMe：分区和整盘都尝试
  snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/device/model", maj, min);
  f = fopen(path, "r");
  if (!f) {
    snprintf(path, sizeof(path), "/sys/dev/block/%u:%u/../device/model", maj, min);
    f = fopen(path, "r");
  }
  if (f) {
    char model[128] = {};
    fgets(model, sizeof(model), f);
    fclose(f);
    for (char *p = model; *p; p++)
      if (*p >= 'A' && *p <= 'Z') *p = *p + ('a' - 'A');
    if (strstr(model, "nvme"))
      return DIOK_NVME;
  }

  return rot == 0 ? DIOK_SSD : DIOK_HDD;
}

static void print_diagnosis(FILE *out, int stats_fd, int file_stats_fd,
                            int block_hist_fd, double interval_s)
{
  fprintf(out,
    "======================================================================\n"
    "  I/O 异常诊断报告\n"
    "======================================================================\n\n");

  int anomaly_count = 0;

  // 收集文件级热点集中度
  unsigned long long total_file_ios = 0;
  unsigned long long top3_ios = 0;
  struct hot_entry top_files[3] = {};
  int nr_top = 0;

  __u64 fkey = 0, fnext;
  while (bpf_map_get_next_key(file_stats_fd, &fkey, &fnext) == 0 && nr_top < 10240) {
    struct file_io_stat fval = {};
    if (bpf_map_lookup_elem(file_stats_fd, &fnext, &fval) != 0) {
      fkey = fnext;
      continue;
    }
    unsigned long long ios = fval.rd_count + fval.wr_count;
    total_file_ios += ios;

    // 维护 top-3
    int pos = nr_top < 3 ? nr_top : -1;
    if (pos < 0) {
      for (int i = 0; i < 3; i++) {
        unsigned long long ti = top_files[i].stat.rd_count + top_files[i].stat.wr_count;
        if (ios > ti) { pos = i; break; }
      }
      if (pos >= 0) {
        for (int i = 2; i > pos; i--) top_files[i] = top_files[i-1];
      }
    }
    if (pos >= 0) {
      top_files[pos].file_key = fnext;
      top_files[pos].stat = fval;
      if (nr_top < 3) nr_top++;
    }

    fkey = fnext;
  }
  for (int i = 0; i < nr_top && i < 3; i++)
    top3_ios += top_files[i].stat.rd_count + top_files[i].stat.wr_count;
  double top3_pct = total_file_ios > 0
    ? (double)top3_ios / (double)total_file_ios * 100.0 : 0;

  // 遍历设备统计做逐设备诊断
  __u32 key = 0, next_key;
  int seq = 0;

  while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
    struct dev_stats val = {};
    if (bpf_map_lookup_elem(stats_fd, &next_key, &val) != 0) {
      key = next_key;
      continue;
    }

    __u32 dev = next_key;
    unsigned int maj = dev >> 20;
    unsigned int min = dev & 0xFFFFF;
    unsigned long long total_ios = val.rd_count + val.wr_count;
    if (total_ios < 10) { key = next_key; continue; }  // 采样太少不做诊断

    seq++;
    int kind = get_disk_kind(dev);

    double iops = (double)total_ios / interval_s;
    double avg_lat_us = (double)val.total_lat_ns / (double)total_ios / 1000.0;
    double avg_qwait_us = (double)val.total_qwait_ns / (double)total_ios / 1000.0;
    double avg_svc_us = (double)val.total_svc_ns / (double)total_ios / 1000.0;
    double p99_us = 0, p999_us = 0;
    {
      unsigned long long accum = 0;
      unsigned long long target99 = (unsigned long long)((double)total_ios * 0.99);
      if (target99 == 0) target99 = 1;
      unsigned long long target999 = (unsigned long long)((double)total_ios * 0.999);
      if (target999 == 0) target999 = 1;
      for (int i = 0; i < 16; i++) {
        accum += val.lat_hist[i];
        if (p99_us == 0 && accum >= target99)
          p99_us = (i == 0) ? 2.0 : (double)(1ULL << (i + 1));
        if (p999_us == 0 && accum >= target999)
          p999_us = (i == 0) ? 2.0 : (double)(1ULL << (i + 1));
      }
    }

    int has_reads = (val.total_rd_blks > 0);
    double miss_rate = has_reads
      ? (double)val.cache_miss_count / (double)val.total_rd_blks * 100.0 : 0;

    int max_qd = 256;
    {
      char qpath[128];
      snprintf(qpath, sizeof(qpath), "/sys/dev/block/%u:%u/queue/nr_requests", maj, min);
      FILE *qf = fopen(qpath, "r");
      if (!qf) {
        snprintf(qpath, sizeof(qpath), "/sys/dev/block/%u:%u/../queue/nr_requests", maj, min);
        qf = fopen(qpath, "r");
      }
      if (qf) { fscanf(qf, "%d", &max_qd); fclose(qf); }
    }
    double qd_usage_pct = max_qd > 0
      ? (double)val.ic_qdepth_max / (double)max_qd * 100.0 : 0;

    // 阈值选择
    double p99_hi, qwait_hi;
    const char *type_label;
    switch (kind) {
    case DIOK_NVME: p99_hi = 5.0;   qwait_hi = 2.0;  type_label = "NVMe"; break;
    case DIOK_SSD:  p99_hi = 20.0;  qwait_hi = 10.0; type_label = "SSD";  break;
    case DIOK_HDD:  p99_hi = 100.0; qwait_hi = 50.0; type_label = "HDD";  break;
    default:        p99_hi = 50.0;  qwait_hi = 25.0; type_label = "unknown"; break;
    }

    // 触发条件收集
    int triggers = 0;
    int flag_lat  = (p99_us > p99_hi);
    int flag_qd   = (qd_usage_pct > 70.0);
    int flag_qwait = (avg_qwait_us > qwait_hi);
    int flag_cache = (has_reads && val.total_rd_blks > 100 && miss_rate > 10.0);
    int flag_hot   = (top3_pct > 70.0);
    triggers = flag_lat + flag_qd + flag_qwait + flag_cache + flag_hot;

    if (triggers == 0) { key = next_key; continue; }

    anomaly_count++;

    // 根因判定
    const char *anomaly_type = NULL;
    const char *root_cause = NULL;
    if (flag_qd && flag_lat) {
      anomaly_type = "I/O 延迟抖动";
      root_cause = "磁盘队列过深 — 并发请求超出设备处理能力，请求在队列中堆积";
    } else if (flag_lat && flag_hot) {
      anomaly_type = "I/O 延迟抖动";
      root_cause = "热点文件访问集中 — 少量文件占用大量 I/O 带宽，导致争抢";
    } else if (flag_cache && flag_lat) {
      anomaly_type = "I/O 延迟抖动";
      root_cause = "页面缓存失效 — 缓存空间被占满，同块数据反复从磁盘重读";
    } else if (flag_qwait && flag_lat) {
      anomaly_type = "I/O 延迟抖动";
      root_cause = "多作业并发争抢 — 请求在调度层排队等待时间显著增加";
    } else if (flag_qd) {
      anomaly_type = "I/O 吞吐波动";
      root_cause = "队列瞬时拥堵 — 短时间内大量 IO 涌入导致处理积压";
    } else if (flag_cache) {
      anomaly_type = "I/O 缓存异常";
      root_cause = "页面缓存频繁失效 — 同块数据被反复读入后又被驱逐";
    } else if (flag_lat) {
      anomaly_type = "I/O 延迟抖动";
      root_cause = "随机读写压力 — 大量小 IO 请求导致设备寻道/寻址开销增大";
    } else {
      anomaly_type = "I/O 异常波动";
      root_cause = "多因素综合 — 建议结合系统日志进一步排查";
    }

    // 输出
    fprintf(out,
      "──────────────────────────────────────────────────────────────────────\n"
      "  [诊断 #%d] 设备 %u:%u (%s)\n"
      "──────────────────────────────────────────────────────────────────────\n\n"
      "  异常类型: %s\n"
      "  关联对象: 块设备 %u:%u\n"
      "  疑似根因: %s\n\n"
      "  关键指标:\n"
      "    P99 时延:     %6.1f us  (阈值: %.0f us, %s)\n"
      "    P99.9 时延:   %6.1f us\n"
      "    平均时延:     %6.1f us\n"
      "    排队等待:     %6.1f us  (阈值: %.0f us)\n"
      "    服务时间:     %6.1f us\n"
      "    IOPS:         %6.0f\n"
      "    队列深度:     %6llu (max) / %d (max kernel), 使用率 %.0f%%\n"
      "    缓存失效率:   %5.1f%%  (%llu / %llu 块)%s\n\n",
      seq, maj, min, type_label,
      anomaly_type,
      maj, min,
      root_cause,
      p99_us, p99_hi, flag_lat ? "!! 超标" : "OK",
      p999_us,
      avg_lat_us,
      avg_qwait_us, qwait_hi,
      avg_svc_us,
      iops,
      val.ic_qdepth_max, max_qd, qd_usage_pct,
      miss_rate, val.cache_miss_count, val.total_rd_blks,
      has_reads ? "" : " (N/A — 无读请求)");

    // 证据列表
    fprintf(out, "  证据:\n");
    int ev_n = 1;
    if (flag_lat)
      fprintf(out, "    %d. P99 时延 %.1f us 超出 %s 阈值 %.0f us\n", ev_n++, p99_us, type_label, p99_hi);
    if (flag_qd)
      fprintf(out, "    %d. 队列深度峰值 %llu，达到内核上限 %d 的 %.0f%%\n", ev_n++, val.ic_qdepth_max, max_qd, qd_usage_pct);
    if (flag_qwait)
      fprintf(out, "    %d. 平均排队等待 %.1f us 显著偏高（阈值 %.0f us），IO 在调度层堆积\n", ev_n++, avg_qwait_us, qwait_hi);
    if (flag_cache)
      fprintf(out, "    %d. 缓存失效率 %.1f%%，同块数据在 %dms 内被重复读取 %llu 次\n", ev_n++, miss_rate, 500, val.cache_miss_count);
    if (flag_hot)
      fprintf(out, "    %d. Top-3 热点文件占全局 IOPS 的 %.1f%%，访问高度集中\n", ev_n++, top3_pct);
    if (!flag_lat && !flag_qd && !flag_qwait && !flag_cache)
      fprintf(out, "    %d. 指标波动幅度较小，建议延长观测窗口确认趋势\n", ev_n++);

    // 热点文件关联
    if (flag_hot && nr_top > 0) {
      fprintf(out, "\n  关联热点文件:\n");
      for (int i = 0; i < nr_top; i++) {
        struct file_io_stat *fs = &top_files[i].stat;
        unsigned long long fios = fs->rd_count + fs->wr_count;
        fprintf(out, "    - %s (comm=%s)  IOPS=%.0f\n",
          fs->fname[0] ? fs->fname : "(unknown)",
          fs->comm[0]  ? fs->comm  : "(unknown)",
          (double)fios / interval_s);
      }
    }

    fprintf(out, "\n");
    key = next_key;
  }

  if (anomaly_count == 0)
    fprintf(out, "  (未检测到明显 I/O 异常 — 所有设备指标在正常范围内)\n\n");

  fprintf(out, "======================================================================\n\n");
  fflush(out);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"用法: %s [选项]\n"
		"\n"
		"I/O 异常观测工具 — 基于 eBPF 实时监测块设备 I/O 性能，\n"
		"采集吞吐、延迟、队列深度等指标。\n"
		"\n"
		"选项:\n"
		"  -i <秒>    采样间隔（默认: %d）\n"
		"  -d <秒>    总运行时长，0 表示持续运行（默认: 0）\n"
		"  -h         显示本帮助信息\n"
		"\n"
		"示例:\n"
		"  sudo %s                  # 默认参数运行\n"
		"  sudo %s -i 5 -d 30      # 每 5 秒采样，运行 30 秒\n",
		prog, DEFAULT_INTERVAL, prog, prog);
}

int main(int argc, char **argv)
{
	int interval = DEFAULT_INTERVAL;
	int duration = 0;

	int opt;
	while ((opt = getopt(argc, argv, "i:d:h")) != -1) {
		switch (opt) {
		case 'i': interval = atoi(optarg); break;
		case 'd': duration = atoi(optarg); break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	if (interval < 1) {
		fprintf(stderr, "采样间隔必须 >= 1\n");
		return 1;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	struct io_anomaly_bpf *skel = io_anomaly_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "无法加载 BPF 程序（需要 root 权限）\n");
		return 1;
	}

	if (io_anomaly_bpf__attach(skel) != 0) {
		fprintf(stderr, "无法挂载 BPF 程序\n");
		io_anomaly_bpf__destroy(skel);
		return 1;
	}

	int stats_fd = bpf_map__fd(skel->maps.dev_stats);
	int req_fd = bpf_map__fd(skel->maps.io_req);
	int block_hist_fd = bpf_map__fd(skel->maps.block_read_hist);

	if (stats_fd < 0 || req_fd < 0) {
		fprintf(stderr, "无法获取 BPF map fd\n");
		io_anomaly_bpf__destroy(skel);
		return 1;
	}
  
  
	struct hotfile_bpf *hot_skel = hotfile_bpf__open_and_load();
	if (!hot_skel) {
	  io_anomaly_bpf__destroy(skel);
		fprintf(stderr, "无法加载 BPF 程序（需要 root 权限）\n");
		return 1;
	}

	if (hotfile_bpf__attach(hot_skel) != 0) {
		fprintf(stderr, "无法挂载 BPF 程序\n");
	  io_anomaly_bpf__destroy(skel);
		hotfile_bpf__destroy(hot_skel);
		return 1;
	}

	int hotfile_stats_fd = bpf_map__fd(hot_skel->maps.file_stats);

	if (hotfile_stats_fd < 0) {
		fprintf(stderr, "无法获取 BPF map fd\n");
	  io_anomaly_bpf__destroy(skel);
		hotfile_bpf__destroy(hot_skel);
		return 1;
	}


	fprintf(stderr, "[*] I/O 异常观测已启动, 采样间隔=%ds\n", interval);
	fprintf(stderr, "[*] 追踪 tracepoint: block_rq_insert / block_rq_issue / block_rq_complete\n");

	time_t start = time(NULL);

	while (!exiting) {
		sleep(interval);

		print_io_report(stdout, stats_fd, req_fd, (double)interval);
		print_cache_thrash_report(stdout, block_hist_fd);
    print_hotfile_report(stdout, hotfile_stats_fd, (double)interval);
		print_diagnosis(stdout, stats_fd, hotfile_stats_fd, block_hist_fd, (double)interval);
    reset_file_stats(hotfile_stats_fd);
		reset_dev_stats(stats_fd);
		reset_block_read_hist(block_hist_fd);

		if (duration > 0 && time(NULL) - start >= duration)
			break;
	}

	fprintf(stderr, "[*] 正在退出...\n");
	io_anomaly_bpf__destroy(skel);
  hotfile_bpf__destroy(hot_skel);

	return 0;
}
