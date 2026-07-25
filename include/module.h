#ifndef MODULE_H
#define MODULE_H

// 模块注册接口 — 新增检测模块无需改 main.c
// 第三方模块 JSON 输出规范（供 history/correlate 消费）:
//   顶层字段: module, timestamp, duration_s, system: { ... }
//   sections[] 中 type=diagnosis 的 findings[] 需含 8 字段:
//   target, is_anomaly, subtype, root_cause, suggestion,
//   time_window, key_metrics: { k:v,... }, evidence: [ ... ]

typedef struct module {
	const char *name;
	const char *desc;
	int (*run)(int argc, char **argv);
	struct module *next;
} module_t;

void module_register(module_t *m);

#define REGISTER_MODULE(_name, _desc, _fn) \
	static module_t _m_##_name = { #_name, _desc, _fn, NULL }; \
	__attribute__((constructor)) static void _reg_##_name(void) { \
		module_register(&_m_##_name); \
	}

#endif
