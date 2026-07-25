// correlate.c — 多维关联分析 (v3.0 规则引擎)
// 用法: eebpf correlate [--window N] [-j]
// 加载全部 5 模块 findings, 时间窗口重叠检查, 规则匹配 10 组关联

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include "../include/storage.h"
#include "../include/module.h"

#define MAX_FINDINGS 32
#define MAX_RESULTS  64
#define MAX_MODULES  5
#define MAX_RULES    64

typedef enum { REL_CAUSAL, REL_CONFIRM, REL_CO_OCCUR } relation_t;

typedef struct {
	relation_t relation;
	int confidence;         // 0-100
	const char *reasoning;  // 推理链, 一行说明
} result_t;

// 信号匹配模式 — 按 subtype 关键词匹配
typedef struct {
	const char *module_a;
	const char *sig_a;       // NULL = 匹配所有
	const char *module_b;
	const char *sig_b;
	int confidence;          // 0-100
	relation_t relation;
	const char *reasoning;
} rule_t;

static rule_t rules[MAX_RULES];
static int n_rules = 0;

// 注册规则
#define RULE(ma, sa, mb, sb, conf, rel, why) \
	rules[n_rules++] = (rule_t){ma, sa, mb, sb, conf, REL_##rel, why}

static void init_rules(void)
{
	if (n_rules > 0) return;

	// === CPU -> Lock (2) ===
	RULE("cpu", "CPU异常占用", "lock", "锁竞争", 85, CAUSAL,
		"锁竞争导致 CPU 空转: lock 等待者 on-CPU 但无实际进展");
	RULE("cpu", "CPU异常占用", "lock", "futex 长期等待", 80, CAUSAL,
		"futex 长期睡眠导致调用者被调度离开 CPU, 形成 CPU 空转假象");

	// === CPU -> Hot (2) ===
	RULE("cpu", "CPU异常占用", "hot", "高频调用", 75, CONFIRM,
		"系统调用风暴验证 CPU 异常: 高频 syscall 是 CPU 占用的直接来源");
	RULE("cpu", "CPU异常占用", "hot", "高频 + 高耗时", 90, CAUSAL,
		"高频+高耗时系统调用是 CPU 异常的强因: 调用频率与耗时的乘积");

	// === CPU -> Mem (3) ===
	RULE("cpu", "CPU异常占用", "mem", "回收抖动", 80, CAUSAL,
		"内存回收抖动触发 kswapd 消耗 CPU: 页面回收需要内核 CPU 时间");
	RULE("cpu", "调度延迟", "mem", "换页颠簸", 70, CAUSAL,
		"换页颠簸引发缺页处理 → 调度延迟增大");
	RULE("cpu", "CPU异常占用", "mem", "OOM", 85, CAUSAL,
		"内存耗尽导致 OOM Killer 扫描进程列表及释放内存, 消耗大量 CPU");

	// === I/O -> CPU (2) ===
	RULE("io", "I/O 延迟抖动", "cpu", "调度延迟", 65, CO_OCCUR,
		"I/O 等待提高 iowait, 减少有效 CPU 时间: 非因果但共现");
	RULE("io", "I/O 延迟抖动", "cpu", NULL, 50, CO_OCCUR,
		"I/O 抖动期间 CPU 可能表现为 idle(iowait), 无 CPU 异常信号");

	// === I/O -> Lock (2) ===
	RULE("io", "缓存失效", "lock", "锁竞争", 60, CO_OCCUR,
		"页缓存失效 + 锁竞争: 可能是文件锁/block 层锁影响 I/O 与并发");
	RULE("io", "热点文件", "lock", "锁竞争", 55, CO_OCCUR,
		"热点文件集中访问 + 锁竞争: 多线程竞争同一文件区域");

	// === I/O -> Hot (2) ===
	RULE("io", "I/O 延迟抖动", "hot", "高耗时", 75, CONFIRM,
		"高耗时 syscall(read/write/fsync) 佐证 I/O 延迟抖动根因");
	RULE("io", "缓存失效", "hot", "高耗时", 70, CAUSAL,
		"页缓存失效导致 read 走磁盘路径: syscall 耗时升高与缓存失效同现");

	// === I/O -> Mem (2, 保留原有 + 扩展) ===
	RULE("io", "缓存失效", "mem", "缓存颠簸", 90, CAUSAL,
		"页缓存驱逐: I/O 缓存失效 + 内存 refault 缓存颠簸, 互相放大");
	RULE("io", "队列瞬时拥堵", "mem", "回收抖动", 85, CAUSAL,
		"回收阻塞 I/O: 直接回收触发大量磁盘写回, I/O 队列拥塞");

	// === Mem -> Hot (2) ===
	RULE("mem", "缺页", "hot", "高频调用", 85, CAUSAL,
		"频繁缺页伴随 mmap/brk 等内存 syscall, syscall 高频验证内存压力来源");
	RULE("mem", "高占用", "hot", "高频调用", 65, CONFIRM,
		"内存高占用 + syscall 高频: 内存申请模式分析");

	// === Mem -> Lock (2) ===
	RULE("mem", "缺页颠簸", "lock", "锁竞争", 60, CO_OCCUR,
		"缺页颠簸可能触发 mmap_sem 争用, 与锁竞争共现");
	RULE("mem", "缺页激增", "lock", "锁竞争", 65, CAUSAL,
		"缺页激增引发内核锁(mmap_sem)等待 → 用户态锁竞争加剧");

	// === Lock -> Hot (2) ===
	RULE("lock", "锁竞争", "hot", "高耗时", 80, CONFIRM,
		"锁竞争导致 futex 高耗时: syscall 层面验证锁等待时间");
	RULE("lock", "futex 长期等待", "hot", "高频调用", 75, CAUSAL,
		"futex 长期等待引发重试 futex 调用: 锁等待→高频 syscall");

	// === 单模块高信度异常, 无其他模块佐证 (2) ===
	RULE("io", "缓存失效", "mem", NULL, 50, CO_OCCUR,
		"I/O 缓存失效偏高, 窗口内无内存异常: 可能是冷数据访问, 非页颠簸");
	RULE("mem", "缓存颠簸", "io", NULL, 50, CO_OCCUR,
		"内存 refault 缓存颠簸, 窗口内无 I/O 缓存失效: 单侧内存压力");
}

static const char *rel_name(relation_t r)
{
	switch (r) {
	case REL_CAUSAL:   return "causal";
	case REL_CONFIRM:  return "confirm";
	case REL_CO_OCCUR: return "co-occur";
	}
	return "unknown";
}

static const char *module_cn(const char *m)
{
	if (strcmp(m, "cpu") == 0)  return "CPU";
	if (strcmp(m, "io") == 0)   return "I/O";
	if (strcmp(m, "mem") == 0)  return "MEM";
	if (strcmp(m, "lock") == 0) return "LOCK";
	if (strcmp(m, "hot") == 0)  return "HOT";
	return m;
}

// 按 rules[] 中出现的模块名加载 findings
typedef struct { const char *name; finding_t *f; int n; } mod_data_t;

static int find_or_load(mod_data_t *mods, int *n_mods, const char *name)
{
	for (int i = 0; i < *n_mods; i++)
		if (strcmp(mods[i].name, name) == 0) return i;

	mod_data_t *md = &mods[*n_mods];
	md->name = name;
	md->f = calloc(MAX_FINDINGS, sizeof(finding_t));
	if (!md->f) { md->n = 0; return *n_mods; }
	if (storage_is_enabled())
		md->n = storage_get_recent_findings(name, 3600, md->f, MAX_FINDINGS);
	else {
		const char *modmap[][2] = {
			{"cpu","report/cpu.json"},{"io","report/io.json"},
			{"mem","report/mem.json"},{"lock","report/lock.json"},
			{"hot","report/hot.json"},{NULL,NULL}};
		for (int j = 0; modmap[j][0]; j++)
			if (strcmp(name, modmap[j][0]) == 0)
				md->n = storage_parse_findings_json(modmap[j][1], md->f, MAX_FINDINGS);
	}
	(*n_mods)++;
	return *n_mods - 1;
}

// subtype 是否包含关键词 (模糊匹配)
static int sig_match(const char *subtype, const char *keyword)
{
	if (!keyword) return 1;
	if (!subtype) return 0;
	return strstr(subtype, keyword) != NULL;
}

// 解析 ISO-8601 timestamp 为 epoch 秒
static double parse_epoch(const char *ts)
{
	struct tm tm = {};
	int sec_int = 0;
	double sec_frac = 0;
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

static void print_text(mod_data_t *mods, int n_mods, int window_s)
{
	printf("多维关联分析 (窗口 ±%ds, %d 条规则)\n\n", window_s, n_rules);

	int count = 0;
	for (int ri = 0; ri < n_rules; ri++) {
		rule_t *r = &rules[ri];
		int ia = find_or_load(mods, &n_mods, r->module_a);
		int ib = find_or_load(mods, &n_mods, r->module_b);

		for (int i = 0; i < mods[ia].n; i++) {
			finding_t *fa = &mods[ia].f[i];
			if (!sig_match(fa->subtype, r->sig_a)) continue;

			if (r->sig_b == NULL) {
				// 单侧规则: A侧命中, B侧无相关信号
				int has_b_signal = 0;
				for (int j = 0; j < mods[ib].n; j++) {
					finding_t *fb = &mods[ib].f[j];
					double ta = parse_epoch(fa->timestamp);
					double tb = parse_epoch(fb->timestamp);
					if (ta == 0 || tb == 0) continue;
					if (ABS_DIFF(ta, tb) > (double)window_s) continue;
					if (mods[ib].f[j].is_anomaly)
						has_b_signal = 1;
				}
				if (!has_b_signal) {
					printf("[%s|%d] %s\n", rel_name(r->relation), r->confidence, r->reasoning);
					printf("  %s 窗口: %s  subtype=%s\n",
						module_cn(r->module_a), fa->time_window, fa->subtype);
					printf("  %s: 窗口内无异常信号\n\n", module_cn(r->module_b));
					count++;
				}
				continue;
			}

			for (int j = 0; j < mods[ib].n; j++) {
				finding_t *fb = &mods[ib].f[j];
				if (!sig_match(fb->subtype, r->sig_b)) continue;

				double ta = parse_epoch(fa->timestamp);
				double tb = parse_epoch(fb->timestamp);
				if (ta == 0 || tb == 0) continue;
				if (ABS_DIFF(ta, tb) > (double)window_s) continue;

				printf("[%s|%d] %s\n", rel_name(r->relation), r->confidence, r->reasoning);
				printf("  %s 窗口: %s  subtype=%s\n",
					module_cn(r->module_a), fa->time_window, fa->subtype);
				printf("  %s 窗口: %s  subtype=%s\n",
					module_cn(r->module_b), fb->time_window, fb->subtype);

				if (fa->n_metrics > 0) {
					printf("  %s 指标:", module_cn(r->module_a));
					for (int k = 0; k < fa->n_metrics; k++)
						printf(" %s=%s", fa->metrics[k].key, fa->metrics[k].val);
					printf("\n");
				}
				if (fb->n_metrics > 0) {
					printf("  %s 指标:", module_cn(r->module_b));
					for (int k = 0; k < fb->n_metrics; k++)
						printf(" %s=%s", fb->metrics[k].key, fb->metrics[k].val);
					printf("\n");
				}
				printf("\n");
				count++;
			}
		}
	}

	if (count == 0)
		printf("(未发现关联异常)\n");
	else
		printf("---\n共 %d 条关联结果\n", count);
}

static void print_json(mod_data_t *mods, int n_mods, int window_s)
{
	printf("{\n");
	printf("  \"module\": \"correlate\",\n");
	printf("  \"window_s\": %d,\n", window_s);
	printf("  \"results\": [\n");

	int count = 0;
	for (int ri = 0; ri < n_rules; ri++) {
		rule_t *r = &rules[ri];
		int ia = find_or_load(mods, &n_mods, r->module_a);
		int ib = find_or_load(mods, &n_mods, r->module_b);

		for (int i = 0; i < mods[ia].n; i++) {
			finding_t *fa = &mods[ia].f[i];
			if (!sig_match(fa->subtype, r->sig_a)) continue;

			if (r->sig_b == NULL) {
				int has_b_signal = 0;
				for (int j = 0; j < mods[ib].n; j++) {
					finding_t *fb = &mods[ib].f[j];
					double ta = parse_epoch(fa->timestamp);
					double tb = parse_epoch(fb->timestamp);
					if (ta == 0 || tb == 0) continue;
					if (ABS_DIFF(ta, tb) > (double)window_s) continue;
					if (mods[ib].f[j].is_anomaly) has_b_signal = 1;
				}
				if (!has_b_signal) {
					if (count > 0) printf(",\n");
					printf("    {\"relation\":\"%s\",\"confidence\":%d,",
						rel_name(r->relation), r->confidence);
					printf("\"reasoning\":\"%s\",", r->reasoning);
					printf("\"%s_window\":\"%s\",",
						r->module_a, fa->time_window);
					printf("\"%s_target\":\"%s\",",
						r->module_a, fa->target);
					printf("\"%s_subtype\":\"%s\"}", r->module_a, fa->subtype);
					count++;
				}
				continue;
			}

			for (int j = 0; j < mods[ib].n; j++) {
				finding_t *fb = &mods[ib].f[j];
				if (!sig_match(fb->subtype, r->sig_b)) continue;

				double ta = parse_epoch(fa->timestamp);
				double tb = parse_epoch(fb->timestamp);
				if (ta == 0 || tb == 0) continue;
				if (ABS_DIFF(ta, tb) > (double)window_s) continue;

				if (count > 0) printf(",\n");
				printf("    {\"relation\":\"%s\",\"confidence\":%d,",
					rel_name(r->relation), r->confidence);
				printf("\"reasoning\":\"%s\",", r->reasoning);
				printf("\"%s_window\":\"%s\",", r->module_a, fa->time_window);
				printf("\"%s_window\":\"%s\",", r->module_b, fb->time_window);
				printf("\"%s_target\":\"%s\",", r->module_a, fa->target);
				printf("\"%s_target\":\"%s\",", r->module_b, fb->target);
				printf("\"%s_subtype\":\"%s\",", r->module_a, fa->subtype);
				printf("\"%s_subtype\":\"%s\"}", r->module_b, fb->subtype);
				count++;
			}
		}
	}

	printf("\n  ],\n  \"count\": %d\n}\n", count);
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

	init_rules();

	mod_data_t mods[MAX_MODULES] = {};
	int n_mods = 0;

	// 从 rules 中收集需要的模块并预加载
	for (int ri = 0; ri < n_rules; ri++) {
		find_or_load(mods, &n_mods, rules[ri].module_a);
		find_or_load(mods, &n_mods, rules[ri].module_b);
	}

	int total_findings = 0;
	for (int i = 0; i < n_mods; i++)
		total_findings += mods[i].n;

	if (total_findings == 0) {
		fprintf(stderr, "eebpf correlate: 无可用数据\n");
		fprintf(stderr, "  先运行各模块采样: sudo ./eebpf <模块> -d 5\n");
		goto cleanup;
	}

	if (json_output)
		print_json(mods, n_mods, window_s);
	else
		print_text(mods, n_mods, window_s);

cleanup:
	for (int i = 0; i < n_mods; i++)
		free(mods[i].f);
	return (total_findings == 0) ? 1 : 0;
}

REGISTER_MODULE(correlate, "多维关联分析", run_correlate);
