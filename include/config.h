#ifndef CONFIG_H
#define CONFIG_H

// 运行时配置，从 eebpf.conf 加载，key=value 格式
// 查找路径: ./eebpf.conf > ~/.eebpf.conf > /etc/eebpf.conf

typedef struct {
	// 全局
	int interval;

	// CPU
	double cpu_threshold;
	int cpu_profile_hz;

	// I/O
	int io_interval;

	// 内存
	int mem_interval;
	double mem_avail_pct;
	double mem_majfault;
	double mem_refault;
	double mem_swapin;
	double mem_direct_stall_ms;
	double mem_retry_ps;
	double mem_fault_ps;

	// 锁
	int lock_futex_warn_us;
	int lock_futex_crit_us;
	int lock_blocked_warn_ms;

	// 系统调用
	int hot_freq_per_sec;
	int hot_lat_us;
	double hot_err_rate;
} eebpf_config;

extern eebpf_config g_cfg;

void config_init(void);
void config_print(void);

#endif
