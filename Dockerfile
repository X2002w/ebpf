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
        bpftool \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
