# openKylin 基础镜像
FROM openkylin/openkylin:latest

ENV DEBIAN_FRONTEND=noninteractive

# 更新软件源并安装基础软件包
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        vim \
        sudo \
        curl \
        wget \
        gnupg \
        ca-certificates \
        git \
        make \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 此层安装ebpf包依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        make \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 从 bpf-next 源码构建 bpftool
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libcap-dev \
        libssl-dev \
        binutils-dev \
        llvm-dev \
        libdebuginfod-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-docutils \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git /tmp/bpf-next && \
    cd /tmp/bpf-next/tools/bpf/bpftool && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/bpf-next

# 从源码构建 stress-ng 和 fio 系统压力测试工具
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libaio-dev \
        libnuma-dev \
        librdmacm-dev \
        libibverbs-dev \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --depth=1 https://github.com/ColinIanKing/stress-ng.git /tmp/stress-ng && \
    cd /tmp/stress-ng && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/stress-ng && \
    git clone --depth=1 https://github.com/axboe/fio.git /tmp/fio && \
    cd /tmp/fio && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/fio

CMD ["/bin/bash"]
