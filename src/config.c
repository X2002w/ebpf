// config.c — 运行时配置文件加载
// 查找路径: ./eebpf.conf > $HOME/.eebpf.conf > /etc/eebpf.conf
// 格式: key = value, # 注释行

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/config.h"

static void set_defaults(void)
{
	g_cfg.interval           = 5;
	g_cfg.cpu_threshold      = 90.0;
	g_cfg.cpu_profile_hz     = 99;
	g_cfg.io_interval        = 3;
	g_cfg.mem_interval       = 3;
	g_cfg.mem_avail_pct      = 20.0;
	g_cfg.mem_majfault       = 200.0;
	g_cfg.mem_refault        = 1000.0;
	g_cfg.mem_swapin         = 500.0;
	g_cfg.mem_direct_stall_ms = 1.0;
	g_cfg.mem_retry_ps       = 50.0;
	g_cfg.mem_fault_ps       = 5000.0;
	g_cfg.lock_futex_warn_us = 10000;
	g_cfg.lock_futex_crit_us = 50000;
	g_cfg.lock_blocked_warn_ms = 100;
	g_cfg.hot_freq_per_sec   = 10000;
	g_cfg.hot_lat_us         = 10000;
	g_cfg.hot_err_rate       = 0.1;
}

eebpf_config g_cfg;

static int parse_line(const char *raw, char *key, size_t ksz, char *val, size_t vsz)
{
	char buf[256];
	strncpy(buf, raw, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	char *s = buf;
	while (isspace(*s)) s++;
	if (*s == '\0' || *s == '#')
		return 0;

	char *eq = strchr(s, '=');
	if (!eq)
		return 0;

	size_t klen = eq - s;
	while (klen > 0 && isspace(s[klen - 1])) klen--;
	if (klen >= ksz) return 0;
	memcpy(key, s, klen);
	key[klen] = '\0';

	char *v = eq + 1;
	while (isspace(*v)) v++;
	strncpy(val, v, vsz - 1);
	val[vsz - 1] = '\0';

	return 1;
}

static void apply_value(const char *key, const char *val)
{
	if (strcmp(key, "interval") == 0)
		g_cfg.interval = atoi(val);
	else if (strcmp(key, "cpu_threshold") == 0)
		g_cfg.cpu_threshold = atof(val);
	else if (strcmp(key, "cpu_profile_hz") == 0)
		g_cfg.cpu_profile_hz = atoi(val);
	else if (strcmp(key, "io_interval") == 0)
		g_cfg.io_interval = atoi(val);
	else if (strcmp(key, "mem_interval") == 0)
		g_cfg.mem_interval = atoi(val);
	else if (strcmp(key, "mem_avail_pct") == 0)
		g_cfg.mem_avail_pct = atof(val);
	else if (strcmp(key, "mem_majfault") == 0)
		g_cfg.mem_majfault = atof(val);
	else if (strcmp(key, "mem_refault") == 0)
		g_cfg.mem_refault = atof(val);
	else if (strcmp(key, "mem_swapin") == 0)
		g_cfg.mem_swapin = atof(val);
	else if (strcmp(key, "mem_direct_stall_ms") == 0)
		g_cfg.mem_direct_stall_ms = atof(val);
	else if (strcmp(key, "mem_retry_ps") == 0)
		g_cfg.mem_retry_ps = atof(val);
	else if (strcmp(key, "mem_fault_ps") == 0)
		g_cfg.mem_fault_ps = atof(val);
	else if (strcmp(key, "lock_futex_warn_us") == 0)
		g_cfg.lock_futex_warn_us = atoi(val);
	else if (strcmp(key, "lock_futex_crit_us") == 0)
		g_cfg.lock_futex_crit_us = atoi(val);
	else if (strcmp(key, "lock_blocked_warn_ms") == 0)
		g_cfg.lock_blocked_warn_ms = atoi(val);
	else if (strcmp(key, "hot_freq_per_sec") == 0)
		g_cfg.hot_freq_per_sec = atoi(val);
	else if (strcmp(key, "hot_lat_us") == 0)
		g_cfg.hot_lat_us = atoi(val);
	else if (strcmp(key, "hot_err_rate") == 0)
		g_cfg.hot_err_rate = atof(val);
}

static void try_load(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return;

	char line[256];
	while (fgets(line, sizeof(line), f)) {
		char key[64], val[64];
		if (parse_line(line, key, sizeof(key), val, sizeof(val)))
			apply_value(key, val);
	}
	fclose(f);
}

void config_init(void)
{
	set_defaults();

	// 优先级: ./eebpf.conf > ~/.eebpf.conf > /etc/eebpf.conf
	// 文件之间不覆盖（先找到的优先）
	const char *home = getenv("HOME");
	try_load("/etc/eebpf.conf");
	if (home) {
		char path[512];
		snprintf(path, sizeof(path), "%s/.eebpf.conf", home);
		try_load(path);
	}
	try_load("./eebpf.conf");

	// CLI 参数覆盖由各模块自行处理（优先级高于配置文件）
}

void config_print(void)
{
	fprintf(stderr, "interval=%d cpu_threshold=%.0f cpu_profile_hz=%d io_interval=%d\n",
		g_cfg.interval, g_cfg.cpu_threshold, g_cfg.cpu_profile_hz, g_cfg.io_interval);
	fprintf(stderr, "mem: avail=%.0f majfault=%.0f refault=%.0f swapin=%.0f stall=%.1fms retry=%.0f fault=%.0f\n",
		g_cfg.mem_avail_pct, g_cfg.mem_majfault, g_cfg.mem_refault,
		g_cfg.mem_swapin, g_cfg.mem_direct_stall_ms, g_cfg.mem_retry_ps, g_cfg.mem_fault_ps);
	fprintf(stderr, "lock: futex_warn=%d futex_crit=%d blocked_warn=%d\n",
		g_cfg.lock_futex_warn_us, g_cfg.lock_futex_crit_us, g_cfg.lock_blocked_warn_ms);
	fprintf(stderr, "hot: freq=%d lat=%d err_rate=%.1f\n",
		g_cfg.hot_freq_per_sec, g_cfg.hot_lat_us, g_cfg.hot_err_rate);
}
