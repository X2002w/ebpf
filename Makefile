# eebpf — eBPF 系统异常观测统一构建

CLANG   ?= clang
BPFTOOL ?= $(or $(wildcard /usr/local/sbin/bpftool),$(wildcard /usr/sbin/bpftool),/usr/sbin/bpftool)

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/riscv64/riscv/')

APP      := eebpf
CFLAGS_COMMON := -Wall -Isrc -Iinclude -Ibuild
CFLAGS_USER := $(CFLAGS_COMMON) -g -O2 -MMD -MP
CFLAGS_BPF := $(CFLAGS_COMMON) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
LDLIBS   := -lbpf -lelf -lz

BUILD_DIR := build


# 查找所有的bpf源文件
BPF_SRCS := $(wildcard src/*.bpf.c)

BPF_OBJS := $(BPF_SRCS:src/%.bpf.c=build/%.bpf.o)
SKEL_HDRS := $(BPF_OBJS:build/%.bpf.o=build/%.skel.h)


ALL_SRCS := $(wildcard src/*.c)

# 过滤bpf源文件
USER_SRCS := $(filter-out src/%.bpf.c, $(ALL_SRCS))
USER_OBJS := $(USER_SRCS:src/%.c=build/%.o)

.PHONY: all clean
all: $(APP)

# 生成vmlinux.h 头文件 -> build 文件夹里
$(BUILD_DIR):
	mkdir -p $@

# 编译 BPF
$(BUILD_DIR)/%.bpf.o: src/%.bpf.c $(BUILD_DIR)/vmlinux.h | $(BUILD_DIR)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/%.o: src/%.c $(SKEL_HDRS) | $(BUILD_DIR)
	$(CLANG) $(CFLAGS_USER) -c $< -o $@

-include $(USER_OBJS:.o=.d)

$(BUILD_DIR)/vmlinux.h: /sys/kernel/btf/vmlinux | $(BUILD_DIR) 
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "Error: Kernel BTF not found. Please enable CONFIG_DEBUG_INFO_BTF"; \
		exit 1; \
	fi
	@$(BPFTOOL) btf dump file $< format c > $@.tmp 2>/dev/null || \
		{ echo "Error: failed to generate vmlinux.h"; rm -f $@.tmp; exit 1; }
	@if [ ! -s $@.tmp ]; then \
		echo "Error: Generate vmlinux.h is empty"; \
		rm -f $@.tmp; \
		exit 1; \
	fi
	@mv $@.tmp $@

$(APP): $(USER_OBJS) 
	$(CLANG) $(CFLAGS_USER) $^ $(LDLIBS) -o $@

clean:
	rm -rf $(BUILD_DIR) $(APP) 
