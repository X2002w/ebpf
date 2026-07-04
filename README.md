# EBPF TOOL

## TODO

- [x] CPU 异常占用或调度延迟
- [x] 设置schedstats 性能分析时开启
- [x] 修复容器环境里bpftool安装失败问题 -> 从源码构建(容器构建时)
- [x] 在docker-compose.yml 里挂载宿主机的必要目录
- [ ] 添加confige文件，存储用户在使用cli工具使得配置信息
- [ ] dev_stats dev_t作为map key, 在设备移除后，map条目变为僵尸数据，主动清理(/proc/partitions)读取设备列表
- [ ] 设备号 dev_t 使用两条路径拿取(rq->part->bd_dev) or (rq->q->disk->major / first_minor)

