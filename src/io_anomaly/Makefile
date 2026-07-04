# libbpf CO-RE Makefile -- io_anomaly

CLANG ?= clang
BPFTOOL ?= $(or $(wildcard /usr/local/sbin/bpftool),$(wildcard /usr/sbin/bpftool),/usr/sbin/bpftool)

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' -e 's/riscv64/riscv/')

APP := io_anomaly
CFLAGS := -g -O2 -Wall
INCLUDES := -I. -I..
SRCS := $(APP).c 
LDLIBS := -lbpf -lelf -lz

.PHONY: all clean
all: $(APP)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(APP).bpf.o: $(APP).bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(APP).bpf.c -o $@

$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(APP): $(APP).c $(APP).skel.h 
	$(CLANG) $(CFLAGS) $(INCLUDES) $(SRCS) $(LDLIBS) -o $@


clean: 
	rm -f $(APP) $(APP).bpf.o $(APP).skel.h vmlinux.h

