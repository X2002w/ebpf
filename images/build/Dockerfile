ARG OPENKYLIN_IMAGE=docker.io/openkylin/openkylin:latest@sha256:0afa429029ffa4c969354d048ce9b3138cbb2bf497e64be89d80c66372c58aa4

FROM ${OPENKYLIN_IMAGE} AS bpftool-builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libelf-dev \
        libcap-dev \
        libssl-dev \
        binutils-dev \
        llvm-dev \
        libdebuginfod-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-docutils \
        git \
        ca-certificates \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git /tmp/bpf-next && \
    cd /tmp/bpf-next/tools/bpf/bpftool && \
    make -j$(nproc) && \
    make prefix=/usr/local install && \
    cd / && \
    rm -rf /tmp/bpf-next

FROM ${OPENKYLIN_IMAGE}
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        libbpf-dev \
        libelf-dev \
        zlib1g-dev \
        make \
        git \
        ca-certificates \
        && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=bpftool-builder /usr/local/sbin/bpftool /usr/local/sbin/bpftool

CMD ["/bin/bash"]
