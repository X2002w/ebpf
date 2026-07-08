// main.c — eebpf 统一入口，子命令分发到各异常检测模块
//
// 用法:
//   eebpf cpu  [options]    CPU 异常检测
//   eebpf io   [options]    I/O 异常检测
//   eebpf mem  [options]    内存异常检测
//   eebpf lock [options]    锁竞争检测
//   eebpf hot  [options]    系统调用热点分析
//   eebpf -v|--version      版本信息
//   eebpf -h|--help         帮助信息

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/cpu_anomaly.h"
#include "../include/io_anomaly.h"

#define VERSION "0.2.0-dev"

// 模块注册表 
typedef struct {
	const char *name;
	const char *desc;
	int (*run)(int argc, char **argv);
} module_t;

static module_t modules[] = {
	{"cpu",  "CPU 异常检测",            run_cpu},
	{"io",   "I/O 异常检测",            run_io},
	{"mem",  "内存异常检测 (未实现)",    NULL},
	{"lock", "锁竞争检测 (未实现)",      NULL},
	{"hot",  "系统调用热点分析 (未实现)", NULL},
	{NULL, NULL, NULL},
};

// 帮助信息 
static void print_help(const char *prog)
{
	printf("eebpf — eBPF 系统异常观测与根因定位工具\n\n");
	printf("用法: %s <子命令> [选项]\n\n", prog);
	printf("子命令:\n");
	for (module_t *m = modules; m->name; m++)
		printf("  %-6s %s\n", m->name, m->desc);
	printf("\n全局选项:\n");
	printf("  -v, --version  显示版本信息\n");
	printf("  -h, --help     显示帮助信息\n");
}

// main 
int main(int argc, char **argv)
{
	const char *prog = argv[0];

	if (argc < 2) {
		print_help(prog);
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
			printf("eebpf version %s\n", VERSION);
			return 0;
		}
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			print_help(prog);
			return 0;
		}
	}

	const char *cmd = argv[1];
	for (module_t *m = modules; m->name; m++) {
		if (strcmp(cmd, m->name) == 0) {
			if (!m->run) {
				fprintf(stderr, "eebpf: '%s' 模块尚未实现\n", cmd);
				return 1;
			}
			return m->run(argc - 1, argv + 1);
		}
	}

	fprintf(stderr, "eebpf: 未知命令 '%s'，使用 -h 查看帮助\n", cmd);
	return 1;
}
