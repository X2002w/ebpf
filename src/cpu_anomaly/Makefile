# libbpf CO-RE Makefile — cpu_anomaly
#
# 构建流程:
#   1) bpftool btf dump        → vmlinux.h
#   2) clang -target bpf       → cpu_anomaly.bpf.o
#   3) bpftool gen skeleton    → cpu_anomaly.skel.h
#   4) clang                   → cpu_anomaly (可执行文件)

CLANG   ?= clang
BPFTOOL ?= /usr/sbin/bpftool

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/riscv64/riscv/')

APP      := cpu_anomaly
CFLAGS   := -g -O2 -Wall
INCLUDES := -I.
LDLIBS   := -lbpf -lelf -lz

.PHONY: all clean
all: $(APP)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(APP).bpf.o: $(APP).bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(APP).bpf.c -o $@

$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(APP): $(APP).c $(APP).skel.h
	$(CLANG) $(CFLAGS) $(INCLUDES) $(APP).c $(LDLIBS) -o $@

clean:
	rm -f $(APP) $(APP).bpf.o $(APP).skel.h vmlinux.h
