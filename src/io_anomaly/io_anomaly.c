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
