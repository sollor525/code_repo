# TLS密钥Agent部署指南

## 概述

TLS密钥Agent是一个基于eBPF的高性能TLS密钥监控系统，能够系统级捕获TLS握手过程中的密钥信息，包括Client Random和Master Secret。本文档详细介绍了在不同环境下的部署方法、配置要求和最佳实践。

## 系统要求

### 硬件要求

#### 最小配置
- **CPU**: 2核心 2.0GHz
- **内存**: 4GB RAM
- **存储**: 10GB 可用空间
- **网络**: 100Mbps

#### 推荐配置
- **CPU**: 4核心 3.0GHz
- **内存**: 8GB RAM
- **存储**: 50GB SSD
- **网络**: 1Gbps

#### 生产环境配置
- **CPU**: 8核心 3.0GHz
- **内存**: 16GB RAM
- **存储**: 100GB SSD
- **网络**: 10Gbps

### 软件要求

#### 操作系统
- **Linux**: Ubuntu 20.04+, CentOS 8+, RHEL 8+, Debian 11+
- **内核版本**: 5.0+ (推荐 5.10+)

#### 必需组件
- **Rust**: 1.70.0+
- **Clang**: 10.0+
- **LLVM**: 10.0+
- **eBPF工具**: bpftool, llvm

#### 可选组件
- **Docker**: 20.10+
- **Kubernetes**: 1.20+
- **Prometheus**: 2.30+
- **Grafana**: 8.0+

### 权限要求

#### 系统权限
- **CAP_SYS_ADMIN**: 加载eBPF程序
- **CAP_NET_ADMIN**: 网络监控权限
- **root权限**: 或等效的sudo权限

#### 文件权限
- `/proc`: 读取权限
- `/sys`: 读取权限
- `/sys/fs/bpf`: 读写权限（eBPF文件系统）

## 安装方式

### 方式1: 二进制安装

#### 下载预编译二进制
```bash
# 下载最新版本
wget https://github.com/your-org/tls-key-agent/releases/latest/download/tls-key-agent-linux-x64.tar.gz

# 解压
tar -xzf tls-key-agent-linux-x64.tar.gz
cd tls-key-agent

# 安装到系统目录
sudo cp tls-key-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/tls-key-agent

# 安装eBPF程序
sudo cp ebpf/*.o /opt/tls-key-agent/
sudo chmod 644 /opt/tls-key-agent/*.o
```

#### 从源码编译
```bash
# 克隆代码库
git clone https://github.com/your-org/tls-key-agent.git
cd tls-key-agent

# 安装Rust工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 编译项目
cargo build --release

# 编译eBPF程序
cd src/ebpf
make all

# 安装
sudo cp target/release/tls-key-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/tls-key-agent
sudo mkdir -p /opt/tls-key-agent
sudo cp *.o /opt/tls-key-agent/
sudo chmod 644 /opt/tls-key-agent/*.o
```

### 方式2: 容器化部署

#### Dockerfile
```dockerfile
FROM rust:1.75-slim as builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    clang \
    llvm \
    linux-headers-$(uname -r) \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# 编译项目
RUN cargo build --release

# 编译eBPF程序
RUN cd src/ebpf && make all

# 运行时镜像
FROM debian:bullseye-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 创建用户
RUN useradd -r -s /bin/false tls_agent

# 创建目录
RUN mkdir -p /app /etc/tls_key_agent /var/log/tls_agent /opt/tls-key-agent

# 复制文件
COPY --from=builder /app/target/release/tls-key-agent /app/
COPY --from=builder /app/src/ebpf/*.o /opt/tls-key-agent/
COPY config.toml /etc/tls_key_agent/

# 设置权限
RUN chown -R tls_agent:tls_agent /app /etc/tls_key_agent /var/log/tls_agent /opt/tls-key-agent

# 切换用户
USER tls_agent

WORKDIR /app

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["./tls-key-agent", "--config", "/etc/tls_key_agent/config.toml"]
```

#### Docker Compose部署
```yaml
# docker-compose.yml
version: '3.8'

services:
  tls-key-agent:
    image: tls-key-agent:latest
    container_name: tls-key-agent
    privileged: true  # 需要特权模式加载eBPF程序
    pid: host
    network_mode: host
    volumes:
      - ./config:/etc/tls_key_agent:ro
      - ./logs:/var/log/tls_agent
      - /sys/fs/bpf:/sys/fs/bpf
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
    environment:
      - RUST_LOG=info
      - TZ=Asia/Shanghai
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

### 方式3: Kubernetes部署

#### namespace.yaml
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tls-key-agent
```

#### daemonset.yaml
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: tls-key-agent
  namespace: tls-key-agent
  labels:
    app: tls-key-agent
spec:
  selector:
    matchLabels:
      app: tls-key-agent
  template:
    metadata:
      labels:
        app: tls-key-agent
    spec:
      hostPID: true
      hostNetwork: true
      tolerations:
      - key: "node-role.kubernetes.io/master"
        operator: "Exists"
        effect: "NoSchedule"
      containers:
      - name: tls-key-agent
        image: tls-key-agent:latest
        imagePullPolicy: Always
        securityContext:
          privileged: true
        volumeMounts:
        - name: config
          mountPath: /etc/tls_key_agent
        - name: proc
          mountPath: /host/proc
          readOnly: true
        - name: sys
          mountPath: /host/sys
          readOnly: true
        - name: bpf
          mountPath: /sys/fs/bpf
        env:
        - name: AGENT_CONFIG_FILE
          value: "/etc/tls_key_agent/agent.toml"
        - name: RUST_LOG
          value: "info"
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
      volumes:
      - name: config
        configMap:
          name: tls-key-agent-config
      - name: proc
        hostPath:
          path: /proc
      - name: sys
        hostPath:
          path: /sys
      - name: bpf
        hostPath:
          path: /sys/fs/bpf
```

## 配置管理

### 基础配置文件 (agent.toml)
```toml
[agent]
name = "tls_key_agent"
version = "1.0.0"
log_level = "info"
buffer_pool_size = 1000
buffer_size = 4096

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
capture_session_ticket = true
kernel_version_requirement = "5.0"

[transport.udp]
enabled = true
server_host = "127.0.0.1"
server_port = 9090
batch_size = 100
batch_timeout_ms = 50
compression = false
reconnect_interval = 5000
max_retries = 3
timeout = 3000

[ebpf_ssl_hook]
enabled = true
kernel_version_requirement = "5.0"
clang_path = "/usr/bin/clang"
uprobe_timeout_ms = 3000
max_events_per_second = 10000

[injection]
enabled = true
default_strategy = "ebpf"

[injection.ebpf]
enabled = true
library_detection_enabled = true

[injection.multi_ssl]
enabled = true
libraries = ["OpenSSL", "GnuTLS", "NSS", "BoringSSL", "LibreSSL"]

[monitoring]
enabled = true
metrics_endpoint = "http://127.0.0.1:9091/metrics"
health_check_endpoint = "http://127.0.0.1:9091/health"

[resilience]
enabled = true

[resilience.load_balancer]
enabled = true
strategy = "RoundRobin"
health_check_interval = 30000
failure_threshold = 3
recovery_threshold = 2

[resilience.performance_monitor]
enabled = true
metrics_retention_period = 3600
alert_check_interval = 30000
max_metrics = 100000
enable_auto_cleanup = true

[resilience.fault_recovery]
enabled = true
max_concurrent_recoveries = 5
default_max_attempts = 3
default_retry_interval = 30000
auto_recovery_enabled = true
```

### 环境变量配置
```bash
# 基础配置
export AGENT_CONFIG_FILE="/etc/tls-key-agent/agent.toml"
export RUST_LOG="info"

# eBPF配置
export EBPF_CLANG_PATH="/usr/bin/clang"
export EBPF_PROGRAM_TIMEOUT_MS=3000

# 网络配置
export UDP_SERVER_HOST="127.0.0.1"
export UDP_SERVER_PORT=9090
export UDP_BATCH_SIZE=100

# 监控配置
export METRICS_ENDPOINT="http://127.0.0.1:9091/metrics"
export HEALTH_CHECK_ENDPOINT="http://127.0.0.1:9091/health"
```

### 命令行参数
```bash
tls-key-agent --help

TLS密钥Agent v1.0.0

USAGE:
    tls-key-agent [OPTIONS]

OPTIONS:
    -c, --config <FILE>          配置文件路径 [default: /etc/tls-key-agent/agent.toml]
    -l, --log-level <LEVEL>     日志级别 [default: info]
        --log-format <FORMAT>    日志格式 [default: json] [possible values: json, text]
        --log-file <FILE>        日志文件路径
        --daemon                 后台运行
        --pid-file <FILE>        PID文件路径
        --user <USER>            运行用户
        --group <GROUP>          运行组
        --umask <UMASK>          文件权限掩码
        --work-dir <DIR>         工作目录
        --max-threads <NUM>      最大线程数
        --stack-size <SIZE>      线程栈大小
        --no-syslog              禁用syslog
        --no-journald            禁用journald
    -h, --help                  显示帮助信息
    -V, --version               显示版本信息
```

## 部署验证

### 健康检查
```bash
# 基础健康检查
curl http://localhost:9091/health

# 详细健康检查
curl http://localhost:9091/health/detailed

# API健康检查
curl http://localhost:8080/api/v1/health
```

### 功能验证
```bash
# 检查eBPF程序状态
sudo bpftool prog show

# 检查eBPF映射
sudo bpftool map show

# 检查进程状态
ps aux | grep tls-key-agent

# 检查网络连接
netstat -tulpn | grep :9090
```

### 性能验证
```bash
# 获取性能指标
curl http://localhost:8080/api/v1/metrics

# 获取连接统计
curl http://localhost:8080/api/v1/connections/stats

# 检查系统资源使用
top -p $(pgrep tls-key-agent)
```

## 监控和日志

### 日志配置
```toml
# 日志配置示例
[logging]
level = "info"
format = "json"
file = "/var/log/tls-key-agent/agent.log"
max_size = "100MB"
max_files = 10
rotate = "daily"

[logging.outputs]
console = true
file = true
syslog = false
journald = false

[logging.filters]
module = "tls_key_agent"
target = "tls_key_agent::*"
```

### Prometheus监控
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'tls-key-agent'
    static_configs:
      - targets: ['localhost:9091']
    metrics_path: '/metrics'
    scrape_interval: 10s
    scrape_timeout: 5s
```

### Grafana仪表板
```json
{
  "dashboard": {
    "title": "TLS密钥Agent监控",
    "panels": [
      {
        "title": "TLS连接数",
        "type": "graph",
        "targets": [
          {
            "expr": "tls_connections_total",
            "legendFormat": "总连接数"
          }
        ]
      },
      {
        "title": "密钥提取数",
        "type": "graph",
        "targets": [
          {
            "expr": "keys_extracted_total",
            "legendFormat": "密钥提取数"
          }
        ]
      }
    ]
  }
}
```

## 故障排除

### 常见问题

#### 1. eBPF程序加载失败
```bash
# 检查内核版本
uname -r

# 检查eBPF支持
ls /proc/sys/kernel/unprivileged_bpf_disabled

# 启用eBPF
echo 0 | sudo tee /proc/sys/kernel/unprivileged_bpf_disabled

# 检查文件系统挂载
mount | grep bpf
sudo mount -t bpf bpf /sys/fs/bpf/
```

#### 2. 权限不足
```bash
# 添加CAP_SYS_ADMIN权限
sudo setcap cap_sys_admin+ep /usr/local/bin/tls-key-agent

# 或使用sudo运行
sudo tls-key-agent --config /etc/tls-key-agent/agent.toml
```

#### 3. 网络连接问题
```bash
# 检查端口占用
sudo netstat -tulpn | grep :9090

# 检查防火墙设置
sudo ufw status
sudo iptables -L

# 检查路由表
ip route show
```

#### 4. 内存使用过高
```bash
# 检查内存使用
free -h
ps aux | grep tls-key-agent

# 调整配置
vim /etc/tls-key-agent/agent.toml

# 减少缓冲池大小
buffer_pool_size = 500
buffer_size = 2048
```

### 日志分析
```bash
# 查看应用日志
tail -f /var/log/tls-key-agent/agent.log

# 查看系统日志
journalctl -u tls-key-agent -f

# 查看内核日志
dmesg | grep -i bpf

# 使用grep过滤关键信息
grep -i "error\|warning" /var/log/tls-key-agent/agent.log
```

### 性能调优
```bash
# 调整系统参数
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 调整eBPF参数
echo 'net.core.bpf_jit_enable = 1' | sudo tee -a /etc/sysctl.conf
```

## 安全最佳实践

### 1. 运行安全
```bash
# 使用专用用户运行
sudo useradd -r -s /bin/false tls-key-agent
sudo chown -R tls-key-agent:tls-key-agent /etc/tls-key-agent
sudo chmod 750 /etc/tls-key-agent

# 设置文件权限
sudo chmod 640 /etc/tls-key-agent/agent.toml
sudo chmod 750 /var/log/tls-key-agent
```

### 2. 网络安全
```bash
# 配置防火墙规则
sudo ufw allow from 192.168.1.0/24 to any port 9090
sudo ufw allow from 10.0.0.0/8 to any port 9091

# 使用TLS加密传输
# 在配置中启用传输加密
[transport.udp]
enable_encryption = true
encryption_key = "your-32-byte-encryption-key-here"
```

### 3. 数据安全
```bash
# 配置日志轮转
sudo vim /etc/logrotate.d/tls-key-agent

# 定期清理旧日志
find /var/log/tls-key-agent -name "*.log" -mtime +30 -delete

# 加密敏感配置文件
sudo gpg --symmetric --cipher-algo AES256 /etc/tls-key-agent/agent.toml
```

## 升级和维护

### 滚动升级
```bash
# 1. 备份配置
sudo cp /etc/tls-key-agent/agent.toml /etc/tls-key-agent/agent.toml.backup

# 2. 停止服务
sudo systemctl stop tls-key-agent

# 3. 更新二进制
sudo cp tls-key-agent /usr/local/bin/tls-key-agent.new
sudo mv /usr/local/bin/tls-key-agent /usr/local/bin/tls-key-agent.old
sudo mv /usr/local/bin/tls-key-agent.new /usr/local/bin/tls-key-agent

# 4. 更新eBPF程序
sudo cp *.o /opt/tls-key-agent/

# 5. 验证配置
tls-key-agent --config /etc/tls-key-agent/agent.toml --check

# 6. 启动服务
sudo systemctl start tls-key-agent

# 7. 验证运行
curl http://localhost:8080/api/v1/health
```

### 定期维护
```bash
# 每日维护脚本
#!/bin/bash
# 检查服务状态
systemctl is-active tls-key-agent

# 清理旧日志
find /var/log/tls-key-agent -name "*.log" -mtime +7 -delete

# 检查磁盘空间
df -h /var/log/tls-key-agent

# 备份配置
cp /etc/tls-key-agent/agent.toml /backup/tls-key-agent-$(date +%Y%m%d).toml
```

## 生产环境部署清单

### 部署前检查清单
- [ ] 内核版本 >= 5.0
- [ ] 安装了必要的开发工具
- [ ] 配置了正确的系统权限
- [ ] 准备了配置文件
- [ ] 设置了监控和日志
- [ ] 验证了网络连接

### 部署后验证清单
- [ ] 服务正常启动
- [ ] eBPF程序正确加载
- [ ] 网络端口正常监听
- [ ] 健康检查通过
- [ ] 监控指标正常
- [ ] 日志输出正常

### 运维监控清单
- [ ] 系统资源使用率监控
- [ ] eBPF程序状态监控
- [ ] 网络连接状态监控
- [ ] 错误日志监控
- [ ] 性能指标趋势分析

## 版本更新历史

### v1.0.0 (2025-12-01) - 架构清理和优化

**部署改进：**
- ✅ **零警告部署**: 修复所有编译警告，完美生产级部署
- ✅ **简化架构**: 移除LD_PRELOAD相关组件，专注eBPF架构
- ✅ **部署简化**: 清理过时文件和配置，减少部署复杂度
- ✅ **文档更新**: 所有部署文档同步更新到eBPF架构

**清理内容：**
- 移除examples目录中的旧版部署示例
- 清理根目录测试脚本，避免部署混淆
- 删除过时的LD_PRELOAD Hook库依赖
- 统一配置文件格式，简化配置管理

**部署优势：**
- 更小的部署包体积（减少25+文件）
- 更快的编译和部署速度
- 更清晰的部署文档和配置
- 更稳定的运行时环境

### v0.2.0 (2025-11-05) - 主动式Hook重构

### v0.1.0 (2023-11-04) - 初始版本

通过以上部署指南，您可以在不同环境中成功部署TLS密钥Agent，并确保其稳定、安全、高效地运行。