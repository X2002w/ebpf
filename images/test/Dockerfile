ARG BASE_IMAGE=ghcr.io/x2002w/eebpf-build:latest
FROM ${BASE_IMAGE} AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        libaio-dev \
        libnuma-dev \
        librdmacm-dev \
        libibverbs-dev \
        git \
        ca-certificates \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
 
# stress-ng 构建
FROM base AS stress-ng-builder
RUN git clone --depth=1 https://github.com/ColinIanKing/stress-ng.git /tmp/stress-ng && \
    cd /tmp/stress-ng && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/stress-ng

# fio 构建
FROM base AS fio-builder
RUN git clone --depth=1 https://github.com/axboe/fio.git /tmp/fio && \
    cd /tmp/fio && \
    ./configure && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/fio

# 最终阶段: 基础镜像 + 运行时库 + 测试工具
FROM base AS final

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libaio3 \
        libnuma1 \
        librdmacm1 \
        libibverbs1 \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY --from=stress-ng-builder /usr/local/bin/stress-ng /usr/local/bin/stress-ng
COPY --from=fio-builder /usr/local/bin/fio /usr/local/bin/fio

CMD ["/bin/bash"]
