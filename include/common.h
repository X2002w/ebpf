#ifndef COMMON_H
#define COMMON_H

// 采样间隔，子模块可提前定义覆盖

#ifndef DEFAULT_INTERVAL
#define DEFAULT_INTERVAL       5
#endif

// 采样与采集
#define DEFAULT_PROFILE_HZ    99      // 栈采样频率 (CPU / Lock)

// 表上限
#define MAX_ROWS              256     // 通用表格最大行数

// 阈值
#define VOLUNTARY_RATIO_HIGH  0.5     // 主动切换占比 > 50% = I/O 等待 / 锁等待模式

#endif
