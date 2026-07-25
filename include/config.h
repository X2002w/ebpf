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
	int cswitch_warn_per_min;   // cswitch/min 警告阈值
	int cswitch_crit_per_min;   // cswitch/min 严重阈值
	int sched_delay_warn_us;    // avg 调度延迟 警告阈值 (us)
	int sched_delay_crit_us;    // avg 调度延迟 严重阈值 (us)
	int busyloop_cs_per_min;    // busy loop 判定: 切换数下限
	double stack_conc_ratio;    // 栈集中度: top1 占比阈值

	// I/O
	int io_interval;
	int min_samples_for_pct;    // P99/P99.9 计算所需最少样本数
	int min_file_ios_for_hot;   // 热点集中判定需要的最少文件IO数

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

	// 存储
	int storage_enabled;

	// 基线自适应判定
	int    baseline_enabled;      // 开关: 历史样本充足时用基线替代固定阈值
	int    baseline_min_samples;  // 启用基线所需最小样本数
	double baseline_z_score;      // 阈值 = mean + z * stddev
	int    baseline_window_sec;   // 基线回看窗口 (秒)
} eebpf_config;

extern eebpf_config g_cfg;

void config_init(void);
void config_print(void);

#endif
