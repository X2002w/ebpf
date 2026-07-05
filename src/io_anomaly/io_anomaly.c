// io_anomaly.c — I/O 异常检测用户态程序
// 加载 BPF skeleton，周期性读取 dev_stats map，打印设备 I/O 统计

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <sys/sysmacros.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "io_anomaly.skel.h"

#define DEFAULT_INTERVAL 3

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
	unsigned long long qdepth_cur;
	unsigned long long qdepth_max;
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

	__u32 key = 0, next_key;
	int seq = 0;
	int has_data = 0;

	while (bpf_map_get_next_key(stats_fd, &key, &next_key) == 0) {
		struct dev_stats val = {};
		if (bpf_map_lookup_elem(stats_fd, &next_key, &val) != 0) {
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
		unsigned int maj = major(dev);
		unsigned int min = minor(dev);

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
			"    最大延迟:     %7.1f us\n\n"
			"  队列深度:\n"
			"    当前瞬时值: %llu\n"
			"    窗口峰值:   %llu\n\n",
			seq, maj, min, dev,
			val.rd_count, rd_mbps,
			val.wr_count, wr_mbps,
			iops,
			avg_lat_us, avg_qwait_us, avg_svc_us, max_lat_us,
			val.qdepth_cur, val.qdepth_max);

		key = next_key;
	}

	if (!has_data)
		fprintf(out, "  (未采集到 I/O 数据 — 请确认系统有磁盘活动)\n\n");

	// 显示残留的 in-flight 请求数（调试用）
	int in_flight = 0;
	__u32 rkey = 0, rnext;
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

	if (stats_fd < 0 || req_fd < 0) {
		fprintf(stderr, "无法获取 BPF map fd\n");
		io_anomaly_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr, "[*] I/O 异常观测已启动, 采样间隔=%ds\n", interval);
	fprintf(stderr, "[*] 追踪 tracepoint: block_rq_insert / block_rq_issue / block_rq_complete\n");

	time_t start = time(NULL);

	while (!exiting) {
		sleep(interval);

		print_io_report(stdout, stats_fd, req_fd, (double)interval);
		reset_dev_stats(stats_fd);

		if (duration > 0 && time(NULL) - start >= duration)
			break;
	}

	fprintf(stderr, "[*] 正在退出...\n");
	io_anomaly_bpf__destroy(skel);

	return 0;
}
