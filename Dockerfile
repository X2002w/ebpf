# 本地开发环境 — 拉取 GHCR 测试镜像（含 stress-ng + fio）
FROM ghcr.io/x2002w/eebpf-test:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        vim sudo curl wget gnupg \
        && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

CMD ["/bin/bash"]
