// correlate.c — 多维关联分析
// 用法: eebpf correlate [--window N] [-j]
// 加载 I/O 和内存 findings，时间窗口重叠检查，4 条关联规则匹配

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include "../include/storage.h"
#include "../include/module.h"

#define MAX_FINDINGS  64
#define MAX_RESULTS   32

typedef enum { CONFIDENCE_HIGH, CONFIDENCE_MEDIUM } confidence_t;

typedef struct {
	const char *rule;
	const char *io_subtype;
	const char *mem_subtype;
	confidence_t confidence;
} correlation_rule_t;

static correlation_rule_t rules[] = {
	{"页缓存驱逐: I/O 缓存失效 + 内存 refault 缓存颠簸",
	 "缓存失效偏高", "内存抖动 (缓存颠簸)", CONFIDENCE_HIGH},
	{"回收阻塞 I/O: I/O 队列拥塞 + 内存直接回收抖动",
	 "队列瞬时拥堵", "内存抖动 (回收抖动)", CONFIDENCE_HIGH},
	{"仅 I/O 缓存失效 (无内存异常)",
	 "缓存失效偏高", NULL, CONFIDENCE_MEDIUM},
	{"仅内存 refault 缓存颠簸 (无 I/O 缓存失效)",
	 NULL, "内存抖动 (缓存颠簸)", CONFIDENCE_MEDIUM},
	{NULL, NULL, NULL, 0},
};

// subtype 是否包含关键字 (模糊匹配)
static int subtype_contains(const char *subtype, const char *keyword)
{
	if (!subtype || !keyword) return 0;
	return strstr(subtype, keyword) != NULL;
}

// 解析 ISO-8601 timestamp 为 epoch 秒
static double parse_epoch(const char *ts)
{
	struct tm tm = {};
	int sec_int = 0;
	double sec_frac = 0;
	// 格式: 2026-07-26T10:30:45.123456 或 2026-07-26T10:30:45
	if (sscanf(ts, "%d-%d-%dT%d:%d:%d.%lf",
		&tm.tm_year, &tm.tm_mon, &tm.tm_mday,
		&tm.tm_hour, &tm.tm_min, &sec_int, &sec_frac) < 5)
		return 0;
	tm.tm_year -= 1900;
	tm.tm_mon -= 1;
	tm.tm_sec = sec_int;
	return (double)mktime(&tm) + sec_frac;
}

#define ABS_DIFF(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))

// 加载指定模块的 findings (SQLite 优先, JSON fallback)
static int load_findings(const char *module, finding_t *out, int max)
{
	if (storage_is_enabled())
		return storage_get_recent_findings(module, 3600, out, max);

	// JSON fallback
	const char *json_files[] = {
		"report/io.json", "report/mem.json",
		"report/cpu.json", "report/lock.json", "report/hot.json",
	};
	const char *mods[] = {"io", "mem", "cpu", "lock", "hot"};
	for (int i = 0; i < 5; i++) {
		if (strcmp(module, mods[i]) == 0)
			return storage_parse_findings_json(json_files[i], out, max);
	}
	return 0;
}

static void print_correlate_text(finding_t *io_f, int io_n,
				  finding_t *mem_f, int mem_n,
				  int window_s)
{
	int result_count = 0;

	printf("多维关联分析 (窗口 ±%ds)\n\n", window_s);

	for (int ri = 0; rules[ri].rule; ri++) {
		correlation_rule_t *r = &rules[ri];

		for (int i = 0; i < io_n; i++) {
			if (r->io_subtype &&
			    !subtype_contains(io_f[i].subtype, r->io_subtype))
				continue;
			for (int j = 0; j < mem_n; j++) {
				if (r->mem_subtype &&
				    !subtype_contains(mem_f[j].subtype, r->mem_subtype))
					continue;

				double ts_io = parse_epoch(io_f[i].timestamp);
				double ts_mem = parse_epoch(mem_f[j].timestamp);
				if (ts_io == 0 || ts_mem == 0) continue;
				if (ABS_DIFF(ts_io, ts_mem) > (double)window_s)
					continue;

				const char *conf = r->confidence == CONFIDENCE_HIGH
					? "HIGH" : "MEDIUM";
				printf("[%s] %s\n", conf, r->rule);
				printf("  I/O 窗口: %s  subtype=%s\n",
					io_f[i].time_window, io_f[i].subtype);
				printf("  MEM 窗口: %s  subtype=%s\n",
					mem_f[j].time_window, mem_f[j].subtype);

				// 输出 IO 关键指标
				if (io_f[i].n_metrics > 0) {
					printf("  I/O 指标:");
					for (int k = 0; k < io_f[i].n_metrics; k++)
						printf(" %s=%s",
							io_f[i].metrics[k].key,
							io_f[i].metrics[k].val);
					printf("\n");
				}
				// 输出 MEM 关键指标
				if (mem_f[j].n_metrics > 0) {
					printf("  MEM 指标:");
					for (int k = 0; k < mem_f[j].n_metrics; k++)
						printf(" %s=%s",
							mem_f[j].metrics[k].key,
							mem_f[j].metrics[k].val);
					printf("\n");
				}
				printf("\n");
				result_count++;
			}
			// 仅 I/O 规则的 mem_subtype 为 NULL, 只遍历内存 findings 中 "无异常" 的
			if (r->mem_subtype == NULL && r->io_subtype &&
			    subtype_contains(io_f[i].subtype, r->io_subtype)) {
				// 检查是否有内存异常在窗口内
				int has_mem_anomaly = 0;
				for (int j = 0; j < mem_n; j++) {
					double ts_io2 = parse_epoch(io_f[i].timestamp);
					double ts_mem2 = parse_epoch(mem_f[j].timestamp);
					if (ts_io2 == 0 || ts_mem2 == 0) continue;
					if (ABS_DIFF(ts_io2, ts_mem2) > (double)window_s)
						continue;
					if (mem_f[j].is_anomaly)
						has_mem_anomaly = 1;
				}
				if (!has_mem_anomaly) {
					const char *conf = "MEDIUM";
					printf("[%s] %s\n", conf, r->rule);
					printf("  I/O 窗口: %s  subtype=%s\n",
						io_f[i].time_window, io_f[i].subtype);
					printf("  MEM: 窗口内无内存异常\n");
					if (io_f[i].n_metrics > 0) {
						printf("  I/O 指标:");
						for (int k = 0; k < io_f[i].n_metrics; k++)
							printf(" %s=%s",
								io_f[i].metrics[k].key,
								io_f[i].metrics[k].val);
						printf("\n");
					}
					printf("\n");
					result_count++;
				}
			}
		}

		// 仅 MEM 规则的 io_subtype 为 NULL
		if (r->io_subtype == NULL && r->mem_subtype) {
			for (int j = 0; j < mem_n; j++) {
				if (!subtype_contains(mem_f[j].subtype, r->mem_subtype))
					continue;
				int has_io_invalid = 0;
				for (int i = 0; i < io_n; i++) {
					double ts_io3 = parse_epoch(io_f[i].timestamp);
					double ts_mem3 = parse_epoch(mem_f[j].timestamp);
					if (ts_io3 == 0 || ts_mem3 == 0) continue;
					if (ABS_DIFF(ts_io3, ts_mem3) > (double)window_s)
						continue;
					if (subtype_contains(io_f[i].subtype, "缓存失效"))
						has_io_invalid = 1;
				}
				if (!has_io_invalid) {
					const char *conf = "MEDIUM";
					printf("[%s] %s\n", conf, r->rule);
					printf("  MEM 窗口: %s  subtype=%s\n",
						mem_f[j].time_window, mem_f[j].subtype);
					printf("  I/O: 窗口内无缓存失效\n");
					if (mem_f[j].n_metrics > 0) {
						printf("  MEM 指标:");
						for (int k = 0; k < mem_f[j].n_metrics; k++)
							printf(" %s=%s",
								mem_f[j].metrics[k].key,
								mem_f[j].metrics[k].val);
						printf("\n");
					}
					printf("\n");
					result_count++;
				}
			}
		}
	}

	if (result_count == 0)
		printf("(未发现关联异常)\n");
	else
		printf("---\n共 %d 条关联结果\n", result_count);
}

static void print_correlate_json(finding_t *io_f, int io_n,
				  finding_t *mem_f, int mem_n,
				  int window_s)
{
	printf("{\n");
	printf("  \"module\": \"correlate\",\n");
	printf("  \"window_s\": %d,\n", window_s);
	printf("  \"results\": [\n");
	int first = 1;

	for (int ri = 0; rules[ri].rule; ri++) {
		correlation_rule_t *r = &rules[ri];
		for (int i = 0; i < io_n; i++) {
			if (r->io_subtype &&
			    !subtype_contains(io_f[i].subtype, r->io_subtype))
				continue;
			for (int j = 0; j < mem_n; j++) {
				if (r->mem_subtype &&
				    !subtype_contains(mem_f[j].subtype, r->mem_subtype))
					continue;
				double ts_io = parse_epoch(io_f[i].timestamp);
				double ts_mem = parse_epoch(mem_f[j].timestamp);
				if (ts_io == 0 || ts_mem == 0) continue;
				if (ABS_DIFF(ts_io, ts_mem) > (double)window_s)
					continue;

				if (!first) printf(",\n");
				first = 0;
				printf("    {\"rule\": \"%s\",", r->rule);
				printf("\"confidence\": \"%s\",",
					r->confidence == CONFIDENCE_HIGH ? "HIGH" : "MEDIUM");
				printf("\"io_time_window\": \"%s\",", io_f[i].time_window);
				printf("\"mem_time_window\": \"%s\",", mem_f[j].time_window);
				printf("\"io_target\": \"%s\",", io_f[i].target);
				printf("\"mem_target\": \"%s\"}", mem_f[j].target);
			}
		}
	}

	printf("\n  ]\n}\n");
}

int run_correlate(int argc, char **argv)
{
	int window_s = 60, json_output = 0;

	static struct option long_opts[] = {
		{"window", required_argument, NULL, 'w'},
		{"help",   no_argument,       NULL, 'h'},
		{0, 0, 0, 0},
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "w:jh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'w': window_s = atoi(optarg); break;
		case 'j': json_output = 1; break;
		case 'h':
			fprintf(stderr, "用法: eebpf correlate [--window N] [-j]\n");
			return 0;
		default:
			return 1;
		}
	}

	finding_t io_findings[MAX_FINDINGS];
	finding_t mem_findings[MAX_FINDINGS];
	int io_n = load_findings("io", io_findings, MAX_FINDINGS);
	int mem_n = load_findings("mem", mem_findings, MAX_FINDINGS);

	if (io_n == 0 && mem_n == 0) {
		fprintf(stderr, "eebpf correlate: 无 I/O 或内存数据\n");
		fprintf(stderr, "  先运行 sudo ./eebpf io -d 5 和 sudo ./eebpf mem -d 5\n");
		return 1;
	}

	if (json_output)
		print_correlate_json(io_findings, io_n, mem_findings, mem_n, window_s);
	else
		print_correlate_text(io_findings, io_n, mem_findings, mem_n, window_s);

	return 0;
}

REGISTER_MODULE(correlate, "多维关联分析", run_correlate);
