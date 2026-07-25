// history.c — 历史趋势查询
// 用法: eebpf history <module> [--limit N] [-j]
//       eebpf history --sql "SELECT ..."

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../include/storage.h"
#include "../include/report_json.h"

static const char *prog;

static void print_usage(void)
{
	fprintf(stderr, "用法: %s history <cpu|io|mem|lock|hot> [--limit N] [-j]\n", prog);
	fprintf(stderr, "      %s history --sql \"SELECT ...\"\n", prog);
}

static void print_timeline_text(const char *module, int limit)
{
	timeline_entry_t entries[64];
	int n = storage_get_timeline(module, limit, entries, 64);

	if (n == 0) {
		printf("(%s) 暂无历史数据\n", module);
		return;
	}

	printf("%-20s %8s %8s\n", "时间窗口", "持续(s)", "异常数");
	printf("-------------------------------------------------\n");
	for (int i = 0; i < n; i++) {
		timeline_entry_t *e = &entries[i];
		printf("%-20s %8.1f %8d\n", e->timestamp, e->duration_s, e->anomaly_count);
	}
	printf("---\n共 %d 条记录\n", n);
}

static void print_json_output(const char *module, int limit)
{
	timeline_entry_t entries[64];
	int n = storage_get_timeline(module, limit, entries, 64);

	printf("{\n");
	printf("  \"module\": \"%s\",\n", module);
	printf("  \"count\": %d,\n", n);
	printf("  \"timeline\": [\n");
	for (int i = 0; i < n; i++) {
		timeline_entry_t *e = &entries[i];
		printf("    {\"timestamp\": \"%s\", \"duration_s\": %.1f, \"anomaly_count\": %d}%s\n",
			e->timestamp, e->duration_s, e->anomaly_count,
			i < n - 1 ? "," : "");
	}
	printf("  ]\n}\n");
}

int run_history(int argc, char **argv)
{
	prog = "eebpf";
	int json_output = 0, limit = 20;
	char *sql = NULL;

	static struct option long_opts[] = {
		{"limit", required_argument, NULL, 'n'},
		{"sql",   required_argument, NULL, 'q'},
		{"help",  no_argument,       NULL, 'h'},
		{0, 0, 0, 0},
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "n:q:jh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'n': limit = atoi(optarg); break;
		case 'q': sql = optarg; break;
		case 'j': json_output = 1; break;
		case 'h': print_usage(); return 0;
		default:  print_usage(); return 1;
		}
	}

	if (!storage_is_enabled()) {
		fprintf(stderr, "eebpf history: 存储未启用，设置 storage_enabled=1\n");
		return 1;
	}

	if (sql)
		return storage_exec_sql(sql) >= 0 ? 0 : 1;

	if (optind >= argc) {
		fprintf(stderr, "eebpf history: 缺少模块名\n");
		print_usage();
		return 1;
	}

	const char *module = argv[optind];

	if (json_output)
		print_json_output(module, limit);
	else
		print_timeline_text(module, limit);

	return 0;
}
