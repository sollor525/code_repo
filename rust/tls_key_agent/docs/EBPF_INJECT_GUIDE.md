# eBPF + 动态注入组合使用指南

## 📋 概述

本指南详细介绍如何使用eBPF + 动态注入组合技术，在不重启服务的情况下监控和提取TLS密钥信息。

## 🎯 核心能力

### ✅ 可以实现的功能
- **无需重启服务**: 对运行中的进程进行动态Hook注入
- **新连接密钥捕获**: 实时监控新建立的TLS连接
- **自动进程发现**: 自动发现系统中的TLS进程
- **持续监控**: 监控新启动的TLS服务
- **高覆盖率**: 可以达到80%+的TLS密钥覆盖率

### ❌ 技术限制
- **现有连接**: 无法提取已经建立的TLS会话密钥
- **依赖条件**: 需要root权限和适当的系统配置
- **版本兼容**: 不同OpenSSL版本需要适配
- **性能影响**: 轻微的性能开销

## 🚀 快速开始

### 1. 系统要求

```bash
# Ubuntu/Debian系统
sudo apt-get update
sudo apt-get install -y \
    clang llvm libbpf-dev \
    build-essential gdb \
    pkg-config libssl-dev

# CentOS/RHEL系统
sudo yum install -y \
    clang llvm libbpf-devel \
    gcc gdb \
    pkgconfig openssl-devel
```

### 2. 编译项目

```bash
# 编译主程序
cd tls_key_agent
cargo build --release --features test-utils

# 编译eBPF程序
clang -O2 -target bpf -c src/ebpf_monitor.c -o ebpf_monitor.o
```

### 3. 一键部署

```bash
# 使用部署脚本（推荐）
sudo ./scripts/ebpf_inject_combo.sh start

# 或者手动执行各个步骤
sudo ./scripts/ebpf_inject_combo.sh discover  # 发现TLS进程
sudo ./scripts/ebpf_inject_combo.sh inject    # 注入Hook
sudo ./scripts/ebpf_inject_combo.sh monitor   # 启动监控
```

## 📖 详细使用方法

### 方法1: 使用部署脚本（推荐）

#### 完整部署
```bash
# 完整部署所有组件
sudo ./scripts/ebpf_inject_combo.sh start
```

输出示例：
```
[2023-11-05 10:00:00] 检查依赖...
[2023-11-05 10:00:01] 编译eBPF程序...
[2023-11-05 10:00:02] 启动eBPF监控...
[2023-11-05 10:00:03] 发现系统中的TLS进程...
PID     Name            CmdLine             TLS    Hooked  LibSSL
--------------------------------------------------------------------------------------------------------------
1234    nginx           nginx: master process  1      0       /usr/lib/x86_64-linux-gnu/libssl.so.1.1
1235    nginx           nginx: worker process  1      0       /usr/lib/x86_64-linux-gnu/libssl.so.1.1
2345    apache2         /usr/sbin/apache2      1      0       /usr/lib/x86_64-linux-gnu/libssl.so.1.1

[2023-11-05 10:00:05] 开始实际注入...
[2023-11-05 10:00:06] 成功注入Hook库到进程 1234
[2023-11-05 10:00:07] 成功注入Hook库到进程 1235
[2023-11-05 10:00:08] 成功注入Hook库到进程 2345

[2023-11-05 10:00:09] 统计信息:
  TLS进程总数: 3
  已Hook进程数: 3
  Hook覆盖率: 100%
```

#### 分步执行
```bash
# 1. 仅发现TLS进程
sudo ./scripts/ebpf_inject_combo.sh discover

# 2. 仅执行Hook注入
sudo ./scripts/ebpf_inject_combo.sh inject

# 3. 仅启动持续监控
sudo ./scripts/ebpf_inject_combo.sh monitor

# 4. 检查注入状态
sudo ./scripts/ebpf_inject_combo.sh status

# 5. 清理所有资源
sudo ./scripts/ebpf_inject_combo.sh cleanup
```

### 方法2: 使用命令行工具

#### 发现TLS进程
```bash
# 表格格式显示
./target/release/dynamic_injector discover --format table

# JSON格式输出
./target/release/dynamic_injector discover --format json

# CSV格式输出
./target/release/dynamic_injector discover --format csv
```

输出示例：
```
PID     Name            CmdLine             TLS    Hooked  LibSSL
--------------------------------------------------------------------------------------------------------------
1234    nginx           nginx: master        1      0       /usr/lib/x86_64-linux-gnu/libssl.so.1.1
1235    nginx           nginx: worker        1      0       /usr/lib/x86_64-linux-gnu/libssl.so.1.1
2345    apache2         /usr/sbin/apache2     1      0       /usr/lib/x86_64-linux-gnu/libssl.so.1.1
3456    mysqld          /usr/sbin/mysqld      1      1       /usr/lib/x86_64-linux-gnu/libssl.so.1.1
4567    postfix         qmgr -l -t unix       1      0       /usr/lib/x86_64-linux-gnu/libssl.so.1.1
```

#### 单个进程注入
```bash
# 注入到指定进程
./target/release/dynamic_injector inject \
    --pid 1234 \
    --library ./target/release/libopenssl_hook.so

# 强制注入（跳过安全检查）
./target/release/dynamic_injector inject \
    --pid 1234 \
    --library ./target/release/libopenssl_hook.so \
    --force
```

#### 批量注入
```bash
# 注入到所有TLS进程（干运行）
./target/release/dynamic_injector inject-all \
    --library ./target/release/libopenssl_hook.so \
    --dry-run

# 实际注入到所有TLS进程
./target/release/dynamic_injector inject-all \
    --library ./target/release/libopenssl_hook.so

# 跳过指定进程
./target/release/dynamic_injector inject-all \
    --library ./target/release/libopenssl_hook.so \
    --skip "1234,3456"
```

#### 持续监控模式
```bash
# 监控新TLS进程并自动注入
./target/release/dynamic_injector monitor \
    --library ./target/release/libopenssl_hook.so \
    --interval 5
```

### 方法3: 手动eBPF操作

#### 加载eBPF程序
```bash
# 编译eBPF程序
clang -O2 -target bpf -c src/ebpf_monitor.c -o ebpf_monitor.o

# 加载到内核
sudo bpftool prog load ebpf_monitor.o /sys/fs/bpf/tls_monitor

# 附加到kprobe
sudo bpftool prog attach name:trace_ssl_write kprobe:SSL_write

# 查看加载的程序
sudo bpftool prog show
```

#### 查看eBPF事件
```bash
# 查看eBPF映射
sudo bpftool map show

# 读取事件（需要自定义程序）
# 可以使用bcc或其他eBPF工具
```

## 🔧 高级配置

### 1. 过滤特定进程

```bash
# 只注入Web服务器进程
./target/release/dynamic_injector discover --format json | \
  jq '.[] | select(.name | test("nginx|apache|httpd")) | .pid' | \
  xargs -I {} ./target/release/dynamic_injector inject \
    --pid {} \
    --library ./target/release/libopenssl_hook.so
```

### 2. 定时任务自动注入

```bash
# 创建cron任务
sudo crontab -e

# 添加以下行，每5分钟检查一次新TLS进程
*/5 * * * * /opt/tls_key_agent/scripts/ebpf_inject_combo.sh discover >> /var/log/tls_key_agent/cron.log 2>&1
*/5 * * * * /opt/tls_key_agent/scripts/ebpf_inject_combo.sh inject >> /var/log/tls_key_agent/cron.log 2>&1
```

### 3. 与systemd集成

```ini
# /etc/systemd/system/tls-key-agent-ebpf.service
[Unit]
Description=TLS Key Agent eBPF + Dynamic Injection
After=network.target
Wants=network.target

[Service]
Type=forking
User=root
Group=root
ExecStart=/opt/tls_key_agent/scripts/ebpf_inject_combo.sh start
ExecStop=/opt/tls_key_agent/scripts/ebpf_inject_combo.sh cleanup
PIDFile=/var/run/tls_key_agent/ebpf_combo.pid
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
# 启用和启动服务
sudo systemctl daemon-reload
sudo systemctl enable tls-key-agent-ebpf
sudo systemctl start tls-key-agent-ebpf
```

## 📊 监控和验证

### 1. 检查Hook状态

```bash
# 检查进程maps
cat /proc/1234/maps | grep openssl_hook

# 检查Hook是否生效
sudo ./scripts/ebpf_inject_combo.sh status
```

### 2. 验证密钥提取

```bash
# 启动TLS Key Agent收集密钥
./target/release/tls_key_agent --config config.toml &

# 测试TLS连接
LD_PRELOAD=/opt/tls_key_agent/libopenssl_hook.so curl -s https://www.baidu.com > /dev/null

# 检查提取的密钥
tail -f /var/log/tls_agent/tls_keys_*.log
```

### 3. 性能监控

```bash
# 监控进程性能
top -p $(pgrep -d',' nginx)

# 检查系统资源
htop
iotop
```

## 🛠️ 故障排除

### 常见问题

#### 1. eBPF程序加载失败

**症状**: `eBPF程序加载失败`

**解决方案**:
```bash
# 检查内核版本
uname -r  # 需要4.9+内核

# 检查BTF信息
ls /sys/kernel/btf/vmlinux

# 启用BTF（如果需要）
echo 1 | sudo tee /sys/kernel/debug/tracing/events/enable
```

#### 2. GDB注入失败

**症状**: `gdb注入失败`

**解决方案**:
```bash
# 检查gdb版本
gdb --version  # 需要支持调试多线程

# 检查进程权限
sudo cat /proc/1234/status | grep Cap

# 尝试使用ptrace模式
# 在脚本中启用ptrace注入
```

#### 3. 权限不足

**症状**: `权限不足，无法注入`

**解决方案**:
```bash
# 确保以root运行
sudo su - root

# 检查安全模块
sudo getenforce  # SELinux状态
sudo sestatus    # SELinux详细状态

# 临时禁用SELinux（仅用于测试）
sudo setenforce 0
```

#### 4. 进程崩溃

**症状**: 注入后进程崩溃

**解决方案**:
```bash
# 检查Hook库兼容性
ldd ./target/release/libopenssl_hook.so

# 使用安全模式注入
./target/release/dynamic_injector inject \
    --pid 1234 \
    --library ./target/release/libopenssl_hook.so \
    --force

# 检查进程日志
dmesg | tail -20
journalctl -u nginx
```

### 调试模式

```bash
# 启用详细日志
RUST_LOG=debug ./target/release/dynamic_injector inject \
    --pid 1234 \
    --library ./target/release/libopenssl_hook.so

# 使用strace跟踪
sudo strace -f -o debug.log ./target/release/dynamic_injector inject \
    --pid 1234 \
    --library ./target/release/libopenssl_hook.so
```

## 📈 性能优化

### 1. 注入优化

```bash
# 批量注入而非单个注入
./target/release/dynamic_injector inject-all \
    --library ./target/release/libopenssl_hook.so

# 并行注入
for pid in $(pgrep nginx); do
    ./target/release/dynamic_injector inject \
        --pid $pid \
        --library ./target/release/libopenssl_hook.so &
done
wait
```

### 2. 监控优化

```bash
# 减少监控频率
./target/release/dynamic_injector monitor \
    --library ./target/release/libopenssl_hook.so \
    --interval 30

# 过滤只监控关键进程
```

## 🔒 安全考虑

### 1. 权限控制
- 仅以root权限运行必要的操作
- 注入前验证进程身份
- 避免注入关键系统进程

### 2. 数据保护
- 密钥日志文件权限限制
- 传输加密保护
- 定期清理敏感数据

### 3. 审计日志
- 记录所有注入操作
- 监控异常行为
- 定期审查日志

## 📚 最佳实践

### 1. 部署建议
- 先在测试环境验证
- 分阶段部署到生产环境
- 监控系统性能影响

### 2. 运维建议
- 定期检查注入状态
- 监控系统资源使用
- 建立告警机制

### 3. 故障恢复
- 准备回滚方案
- 保留原始进程状态
- 建立应急流程

---

**使用eBPF + 动态注入组合，您可以在不重启服务的情况下，实现对运行中TLS进程的密钥监控，显著提高TLS密钥的捕获覆盖率！**