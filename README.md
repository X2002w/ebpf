# EBPF TOOL

## TODO

- [x] CPU 异常占用或调度延迟
- [x] 设置schedstats 性能分析时开启
- [x] 修复容器环境里bpftool安装失败问题 -> 从源码构建(容器构建时)
- [x] 在docker-compose.yml 里挂载宿主机的必要目录
- [ ] 添加confige文件，存储用户在使用cli工具使得配置信息
- [x] io 异常
- [x] dev_stats dev_t作为map key, 在设备移除后，map条目变为僵尸数据，主动清理(/proc/partitions)读取设备列表
- [x] 设备号 dev_t 使用两条路径拿取(rq->part->bd_dev) or (rq->q->disk->major / first_minor)
- [x] 使用另外的fio测试命令，原测试命令体现不出io异常
- [x] 考虑去除ii_qdepth
- [x] ai诊断时, 添加原始系统设备数据, 为BPF 得到的基础数据做参考
- [x] io 缓存失效 检测同块短时间内重复读，即缓存失效(cache 空间被占满)
- [ ] io缓存失效 <- 内存抖动佐证 (多维关联分析)
- [x] 重构项目
- [x] cicd自动构建发布镜像
- [x] 将下载LLVM从build test action移到dockr build action 中
- [ ] 将各部分监测程序的公共宏放置再一起 or 使用config文件编辑
- [ ] 使用sqlite存储历史数据
- [ ] 加前瞻性6.1, 6.6, 6.12, stable —— stable 标签自动追新内核，将来内核更新破坏兼容性时 CI 会第一时间红 
- [ ] 重构文档输出报告

