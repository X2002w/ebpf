#!/bin/bash
set -e

# 确保容器已启动
sudo docker compose up -d

# 进入容器并切换到挂载的工作目录
sudo docker compose exec openkylin bash -c "cd /workspace && exec bash"
