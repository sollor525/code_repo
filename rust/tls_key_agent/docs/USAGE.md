# TLS Key Agent 使用指南

## 🎯 架构选择：Agent vs Hook库

**重要更新**: TLS Key Agent现在支持**两种架构模式**，根据需求选择：

### 🚀 模式1: 仅Hook库 (推荐90%用户)

**特点**: 极简部署，无需Agent进程，直接Hook SSL函数提取密钥

```bash
# 一条命令搞定，无需任何配置
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com
cat /tmp/openssl_keys_all.log
```

**优势**:
- ✅ **零配置**: 无需配置文件，无需Agent进程
- ✅ **极简部署**: 一条命令立即可用
- ✅ **高性能**: 直接Hook，无中间层开销
- ✅ **高可靠**: 无进程间通信故障点

**适用场景**:
- 个人开发和调试
- 安全渗透测试
- Wireshark流量解密
- 单机密钥收集

### 🏢 模式2: Agent + Hook组合 (企业级)

**特点**: 完整的企业级密钥管理，支持集中管理、远程收集、复杂过滤

```bash
# 1. 启动Agent进程
./target/release/tls_key_agent --config agent_config.toml &

# 2. 应用使用Hook库
LD_PRELOAD=./libtls_agent_hook.so your_application
```

**企业级功能**:
- ✅ **集中管理**: TOML配置文件驱动的规则管理
- ✅ **远程收集**: TCP传输到中央服务器
- ✅ **复杂过滤**: 五元组、进程名、时间范围过滤
- ✅ **实时监控**: Agent状态和性能监控
- ✅ **文件轮转**: 自动日志文件管理

## 概述

本指南详细介绍TLS Key Agent的**两种使用模式**。项目采用**主动式Hook架构**，通过直接Hook SSL函数实现更可靠、更直接的密钥提取，完全摆脱了对OpenSSL Keylog回调的依赖。

## 🚀 核心特性

- **主动式Hook**: 基于SSL_write/SSL_read等函数的直接密钥提取
- **多算法支持**: Client Random和Master Secret的多种提取策略
- **智能验证**: 熵值检测和密钥有效性验证
- **高兼容性**: 支持多种OpenSSL版本
- **高性能**: 线程安全，支持高并发场景

## 目录

1. [快速开始](#快速开始)
2. [安装部署](#安装部署)
3. [基础配置](#基础配置)
4. [使用场景](#使用场景)
5. [高级配置](#高级配置)
6. [监控和维护](#监控和维护)
7. [故障排除](#故障排除)
8. [最佳实践](#最佳实践)

## 快速开始

### 系统要求

- **操作系统**: Linux (推荐Ubuntu 20.04+, CentOS 8+)
- **CPU**: x86_64架构
- **内存**: 最少512MB，推荐2GB+
- **磁盘空间**: 最少100MB
- **网络**: 能够访问目标TLS服务
- **权限**: root权限或目标进程的适当权限

### 一键启动（主动式Hook）

```bash
# 1. 下载并编译Hook库
git clone <repository-url>
cd tls_key_agent

# 编译C语言Hook库
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 可选：编译Rust库
cargo build --release

# 2. 快速测试
export SSLKEYLOGFILE=/tmp/test_keys.log
LD_PRELOAD=./libtls_agent_hook.so curl -s https://www.baidu.com > /dev/null

# 3. 验证密钥提取结果
ls -la /tmp/test_keys.log
cat /tmp/test_keys.log
```

### 验证Hook是否正常工作

```bash
# 检查Hook初始化日志
LD_PRELOAD=./libtls_agent_hook.so curl -s https://example.com 2>&1 | grep "TLS Agent"

# 应该看到类似输出：
# [TLS Agent] OpenSSL Hook 初始化成功
# [TLS Agent] SSL_write: 主动提取TLS密钥
```

## 安装部署

### 源码编译

```bash
# 克隆仓库
git clone <repository-url>
cd tls_key_agent

# 安装Rust工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 编译项目
cargo build --release --features test-utils

# 验证编译结果
ls -la target/release/tls_key_agent
ls -la target/release/libopenssl_hook.so
```

### 系统服务安装

#### 创建systemd服务

```bash
# 创建服务文件
sudo tee /etc/systemd/system/tls-key-agent.service > /dev/null <<EOF
[Unit]
Description=TLS Key Agent
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/tls_key_agent
ExecStart=/opt/tls_key_agent/tls_key_agent --config /etc/tls_key_agent/config.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 安装文件
sudo mkdir -p /opt/tls_key_agent /etc/tls_key_agent
sudo cp target/release/tls_key_agent /opt/tls_key_agent/
sudo cp target/release/libopenssl_hook.so /opt/tls_key_agent/
sudo cp config.toml /etc/tls_key_agent/

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable tls-key-agent
sudo systemctl start tls-key-agent

# 检查状态
sudo systemctl status tls-key-agent
```

### Docker部署

```dockerfile
# Dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl1.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/tls_key_agent .
COPY --from=builder /app/target/release/libopenssl_hook.so .
COPY config.toml .

EXPOSE 8080
CMD ["./tls_key_agent", "--config", "config.toml"]
```

```bash
# 构建镜像
docker build -t tls-key-agent .

# 运行容器
docker run -d \
  --name tls-key-agent \
  -p 8080:8080 \
  -v $(pwd)/config.toml:/app/config.toml \
  tls-key-agent
```

## 基础配置

### 创建配置文件

```bash
# 复制模板配置
cp config.toml.example config.toml

# 编辑配置文件
nano config.toml
```

### 基础配置示例

```toml
[agent]
name = "tls_key_agent"
log_level = "info"
buffer_pool_size = 1000
buffer_size = 8192

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
library_path = "./target/release/libopenssl_hook.so"

[transport]
enabled_transports = ["File"]

[transport.file]
enabled = true
directory = "/var/log/tls_agent"
filename_pattern = "tls_keys_{timestamp}.log"
max_file_size = "100MB"
max_files = 10

# 基础过滤规则
[[filters]]
name = "https_traffic"
enabled = true
priority = 100
five_tuple = { dst_port = 443 }
```

### 配置验证

```bash
# 验证配置文件
./target/release/tls_key_agent --config config.toml --check

# 测试配置
./target/release/tls_key_agent --config config.toml --dry-run
```

## 使用场景

### 🎯 关键概念：LD_PRELOAD工作机制

**重要理解**：
- **LD_PRELOAD只影响新进程**: 已经运行的进程不会加载新的Hook库
- **"重启"实际是重新启动进程**: 不是为了应用配置，而是为了加载Hook库
- **无需复杂配置**: 主动式Hook通过环境变量直接工作

### 场景1: 监控Nginx HTTPS流量（主动式Hook）

```bash
# 1. 编译Hook库
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 2. 设置密钥输出文件（可选）
export SSLKEYLOGFILE=/tmp/nginx_tls_keys.log

# 3. 停止现有Nginx进程（可选）
sudo systemctl stop nginx

# 4. 使用LD_PRELOAD启动Nginx（主动式Hook方式）
sudo LD_PRELOAD=$(pwd)/libtls_agent_hook.so systemctl start nginx

# 或者直接启动Nginx二进制（测试环境）
sudo LD_PRELOAD=$(pwd)/libtls_agent_hook.so /usr/sbin/nginx -g 'daemon off;'

# 5. 验证密钥提取
ls -la /tmp/nginx_tls_keys.log /tmp/openssl_keys_all.log
tail -f /tmp/openssl_keys_all.log
```

**🔧 重要说明**：
- **无需独立Agent**: 主动式Hook直接工作，无需启动tls_key_agent进程
- **新进程生效**: LD_PRELOAD只对**新启动**的进程生效
- **无需配置文件**: Hook库通过环境变量直接工作

### 场景2: 监控Apache HTTP Server（主动式Hook）

```bash
# 1. 编译Hook库（如果还没有编译）
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 2. 设置密钥输出文件
export SSLKEYLOGFILE=/tmp/apache_tls_keys.log

# 3. 停止现有Apache进程
sudo systemctl stop apache2

# 4. 使用LD_PRELOAD启动Apache（主动式Hook方式）
sudo LD_PRELOAD=$(pwd)/libtls_agent_hook.so systemctl start apache2

# 或者使用apache2ctl
sudo LD_PRELOAD=$(pwd)/libtls_agent_hook.so apache2ctl start

# 5. 验证密钥提取
ls -la /tmp/apache_tls_keys.log /tmp/openssl_keys_all.log
tail -f /tmp/openssl_keys_all.log
```

**🔧 重要说明**：
- **无需配置文件**: 主动式Hook通过LD_PRELOAD直接工作
- **新进程生效**: 只有新启动的Apache进程才会加载Hook库
- **无需密钥收集服务器**: 密钥直接写入文件，无需TCP传输

### 场景3: 监控邮件服务器(SMTP over TLS)（主动式Hook）

```bash
# 1. 编译Hook库（如果还没有编译）
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 2. 设置邮件服务的密钥输出文件
export SSLKEYLOGFILE=/tmp/postfix_tls_keys.log

# 3. 停止Postfix服务
sudo systemctl stop postfix

# 4. 使用LD_PRELOAD启动Postfix（主动式Hook方式）
sudo LD_PRELOAD=$(pwd)/libtls_agent_hook.so systemctl start postfix

# 5. 测试邮件发送和TLS密钥提取
echo "Test TLS Key Extraction" | mail -s "TLS Hook Test" user@example.com

# 6. 验证密钥提取
ls -la /tmp/postfix_tls_keys.log /tmp/openssl_keys_all.log
tail -f /tmp/openssl_keys_all.log
```

**🔧 重要说明**：
- **无需过滤规则配置**: 主动式Hook自动处理所有TLS连接
- **支持多种端口**: 自动捕获587 (STARTTLS) 和465 (SMTPS) 的密钥
- **无需独立Agent**: Hook库直接工作，无需额外的Agent进程

### 场景4: 开发环境调试

```bash
# 1. 启动调试模式Agent
RUST_LOG=debug ./target/release/tls_key_agent --config config.toml &

# 2. 测试TLS应用
LD_PRELOAD=./target/release/libopenssl_hook.so \
python3 -c "
import ssl
import socket
context = ssl.create_default_context()
with socket.create_connection(('www.baidu.com', 443)) as sock:
    with context.wrap_socket(sock, server_hostname='www.baidu.com') as ssock:
        ssock.send(b'GET / HTTP/1.1\\r\\nHost: www.baidu.com\\r\\n\\r\\n')
        print(ssock.recv(1024))
"

# 3. 查看调试日志
tail -f /var/log/tls_key_agent/debug.log
```

## 高级配置

### 复杂过滤规则

```toml
# 多条件组合过滤
[[filters]]
name = "internal_nginx"
enabled = true
priority = 100
five_tuple = {
    src_ip = "192.168.0.0/16",
    dst_port = 443,
    protocol = "TCP"
}
process_name = "nginx"
time_range = {
    start = "09:00:00",
    end = "18:00:00",
    timezone = "Asia/Shanghai"
}

# 排除特定流量
[[filters]]
name = "exclude_monitoring"
enabled = true
priority = 200
five_tuple = {
    src_ip = "10.0.0.0/8"
}
action = "exclude"

# 自定义标签
[[filters]]
name = "payment_gateway"
enabled = true
priority = 50
five_tuple = {
    dst_ip = "203.0.113.0/24",
    dst_port = 443
}
custom_tags = ["payment", "critical"]
```

### TCP传输配置

```toml
[transport]
enabled_transports = ["Tcp"]

[transport.tcp]
enabled = true
server_host = "192.168.1.100"
server_port = 9999
reconnect_interval = 5
max_reconnect_attempts = 10
timeout = 30
keepalive = true
compression = "gzip"
encryption = {
    enabled = true,
    cert_file = "/etc/tls_agent/client.crt",
    key_file = "/etc/tls_agent/client.key",
    ca_file = "/etc/tls_agent/ca.crt"
}
```

### 高性能配置

```toml
[agent]
name = "tls_key_agent_high_perf"
log_level = "warn"  # 减少日志输出
buffer_pool_size = 10000  # 增大缓冲池
buffer_size = 16384       # 增大缓冲区
worker_threads = 8        # 多线程处理

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
batch_size = 100           # 批量处理
batch_timeout = 100        # 批量超时(ms)

[transport.file]
enabled = true
directory = "/var/log/tls_agent"
filename_pattern = "tls_keys_{timestamp}_{pid}.log"
max_file_size = "1GB"
max_files = 50
compression = true
```

### 安全配置

```toml
[security]
enabled = true
allowed_users = ["root", "tls_agent"]
allowed_groups = ["tls_agent"]
require_root = false
max_sessions_per_process = 1000

[encryption]
enabled = true
algorithm = "AES-256-GCM"
key_rotation_interval = 3600  # 1小时
key_file = "/etc/tls_agent/encryption.key"

[audit]
enabled = true
log_file = "/var/log/tls_agent/audit.log"
log_level = "info"
retention_days = 90
```

## 监控和维护

### 日志配置

```toml
[logging]
level = "info"
file = "/var/log/tls_key_agent/agent.log"
max_file_size = "100MB"
max_files = 10
console_output = true
structured_format = true

[logging.audit]
enabled = true
file = "/var/log/tls_key_agent/audit.log"
include_session_data = false
anonymize_ip = true
```

### 性能监控

```bash
# 使用内置监控工具
./target/release/verify_keys stats --interval 5

# 系统资源监控
htop -p $(pgrep tls_key_agent)
iotop -p $(pgrep tls_key_agent)

# 网络连接监控
netstat -anp | grep tls_key_agent
ss -tuln | grep 9999
```

### 日志分析

```bash
# 查看密钥提取日志
tail -f /var/log/tls_agent/tls_keys_*.log

# 分析会话统计
grep "CLIENT_RANDOM" /var/log/tls_agent/*.log | wc -l

# 查看错误日志
grep -i error /var/log/tls_key_agent/agent.log

# 分析性能指标
grep "processing_time" /var/log/tls_key_agent/agent.log | \
  awk '{print $NF}' | sort -n
```

### 数据备份

```bash
#!/bin/bash
# backup_tls_keys.sh

BACKUP_DIR="/backup/tls_agent/$(date +%Y%m%d)"
LOG_DIR="/var/log/tls_agent"
CONFIG_DIR="/etc/tls_key_agent"

mkdir -p "$BACKUP_DIR"

# 备份日志文件
tar -czf "$BACKUP_DIR/logs.tar.gz" "$LOG_DIR/"

# 备份配置文件
tar -czf "$BACKUP_DIR/config.tar.gz" "$CONFIG_DIR/"

# 清理旧备份
find /backup/tls_agent -type d -mtime +30 -exec rm -rf {} \;

echo "备份完成: $BACKUP_DIR"
```

## 故障排除

### 常见问题

#### 1. LD_PRELOAD不生效

**症状**: 密钥没有被提取

**排查步骤**:
```bash
# 检查库文件是否存在
ls -la ./target/release/libopenssl_hook.so

# 检查库文件依赖
ldd ./target/release/libopenssl_hook.so

# 检查进程是否加载了Hook库
cat /proc/$(pidof nginx)/maps | grep openssl_hook

# 调试LD_PRELOAD
LD_PRELOAD=./target/release/libopenssl_hook.so \
LD_DEBUG=libs \
curl -s https://www.baidu.com > /dev/null
```

**解决方案**:
```bash
# 确保库文件路径正确
export LD_LIBRARY_PATH=$(pwd)/target/release:$LD_LIBRARY_PATH

# 使用绝对路径
LD_PRELOAD=/opt/tls_key_agent/libopenssl_hook.so nginx

# 检查文件权限
chmod 644 ./target/release/libopenssl_hook.so
```

#### 2. 网络连接失败

**症状**: TCP传输连接不上

**排查步骤**:
```bash
# 检查目标服务器是否可达
telnet 192.168.1.100 9999

# 检查防火墙
sudo iptables -L -n | grep 9999
sudo ufw status

# 检查端口占用
netstat -tuln | grep 9999

# 测试网络连通性
ping 192.168.1.100
```

**解决方案**:
```bash
# 修改防火墙规则
sudo iptables -A INPUT -p tcp --dport 9999 -j ACCEPT

# 更改传输配置
[transport.tcp]
server_host = "127.0.0.1"  # 使用本地回环
server_port = 19999        # 使用其他端口
```

#### 3. 权限不足

**症状**: 无法访问目标进程或文件

**排查步骤**:
```bash
# 检查运行用户
id

# 检查目标进程权限
ps aux | grep nginx
ls -la /proc/$(pidof nginx)/fd/

# 检查目录权限
ls -la /var/log/tls_agent/
```

**解决方案**:
```bash
# 使用root权限运行
sudo ./target/release/tls_key_agent --config config.toml

# 创建专用用户
sudo useradd -r -s /bin/false tls_agent
sudo chown -R tls_agent:tls_agent /var/log/tls_agent/
```

#### 4. 内存泄漏

**症状**: 内存使用持续增长

**排查步骤**:
```bash
# 监控内存使用
watch -n 1 'ps aux | grep tls_key_agent'

# 使用valgrind检测
valgrind --tool=memcheck --leak-check=full \
         ./target/release/tls_key_agent --config config.toml

# 查看堆内存使用
cat /proc/$(pidof tls_key_agent)/status | grep -i heap
```

**解决方案**:
```bash
# 调整缓冲池大小
[agent]
buffer_pool_size = 500      # 减少缓冲池
buffer_size = 4096          # 减小缓冲区

# 启用定期清理
[extraction]
cleanup_interval = 300      # 5分钟清理一次
session_timeout = 3600      # 1小时超时
```

### 调试模式

```bash
# 启用详细日志
RUST_LOG=debug ./target/release/tls_key_agent --config config.toml

# 使用GDB调试
gdb --args ./target/release/tls_key_agent --config config.toml

# 内存调试
MALLOC_CHECK_=2 ./target/release/tls_key_agent --config config.toml

# 系统调用跟踪
strace -f -o trace.log ./target/release/tls_key_agent --config config.toml
```

## 最佳实践

### 1. 部署建议

- **生产环境**: 使用systemd管理服务，配置自动重启
- **测试环境**: 使用Docker容器，便于环境隔离
- **监控**: 部署Prometheus/Grafana监控Agent状态
- **日志**: 使用ELK Stack集中管理日志

### 2. 安全建议

- **权限控制**: 以最小权限原则运行Agent
- **数据加密**: 启用传输和存储加密
- **访问控制**: 限制API访问权限
- **审计日志**: 启用完整的操作审计

### 3. 性能优化

- **批量处理**: 启用批量传输减少网络开销
- **缓冲优化**: 根据负载调整缓冲池大小
- **异步处理**: 确保所有I/O操作都是异步的
- **资源限制**: 设置合理的资源使用限制

### 4. 运维建议

- **定期备份**: 备份配置文件和重要日志
- **版本管理**: 使用版本控制管理配置变更
- **测试验证**: 在测试环境验证配置变更
- **文档更新**: 及时更新操作文档

### 5. 故障恢复

- **自动重启**: 配置服务自动重启机制
- **故障转移**: 配置备用传输通道
- **数据恢复**: 建立数据恢复流程
- **应急预案**: 制定故障应急预案

---

*使用指南版本: v0.1.0*
*最后更新: 2023-11-04*