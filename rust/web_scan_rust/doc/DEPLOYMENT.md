# 部署和配置指南 - 生产环境部署

## 🚀 **概述**

本指南详细说明如何在生产环境中部署和配置Web安全扫描系统，包括单机部署、集群部署、Docker容器化、Kubernetes编排和监控配置。

## 🏗️ **系统架构**

### 部署架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                     Web安全扫描系统架构                              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │  负载均衡器  │    │  Web扫描节点  │    │  监控系统   │    │
│  │  (Nginx/HAProxy)│    │  (Rust Engine) │    │ (Prometheus)  │    │
│  └─────────────┘    └─────────────┘    └─────────────┘    │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                 高可用集群模式                                │    │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ │    │
│  │  │ 节点1   │  │ 节点2   │  │ 节点3   │  │ 节点N   │ │    │
│  │  │ (Primary)│  │(Backup) │  │(Worker) │  │(Worker) │ │    │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘ │    │
│  └─────────────────────────────────────────────────────────────┘    │
│         │                    │                    │              │
│         ▼                    ▼                    ▼              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    │
│  │  存储系统    │    │  数据库      │    │  日志系统    │    │
│  │  (Redis/SSD) │    │ (PostgreSQL) │    │ (ELK Stack)  │    │
│  └─────────────┘    └─────────────┘    └─────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### 组件说明

| 组件 | 角色说明 | 推荐配置 | 高可用方案 |
|------|----------|----------|------------|
| **负载均衡器** | 流量分发和健康检查 | Nginx/HAProxy, 4C8G | 双机热备+Keepalived |
| **Web扫描节点** | 威胁检测和规则匹配 | 8C16G+100GB SSD | 主从复制+自动故障转移 |
| **规则管理** | 集中式规则分发和更新 | 独立服务器/Redis集群 | 多节点同步+版本控制 |
| **存储系统** | 会话状态和缓存数据 | Redis Cluster/内存数据库 | 分片+副本+持久化 |
| **监控告警** | 性能监控和异常告警 | Prometheus+Grafana | 多地域+多层级监控 |
| **日志系统** | 安全日志和审计追踪 | ELK Stack/Loki | 分布式收集+长期存储 |

## 🔧 **环境准备**

### 硬件要求

#### 最小配置（测试环境）
- **CPU**: 4核心 Intel/AMD x86_64
- **内存**: 8GB RAM
- **存储**: 100GB SSD
- **网络**: 1Gbps 网络带宽

#### 生产配置（推荐）
- **CPU**: 8核心 Intel/AMD x86_64, 支持AVX2指令集
- **内存**: 32GB+ RAM (建议64GB)
- **存储**: 1TB+ NVMe SSD (规则缓存+日志)
- **网络**: 10Gbps+ 网络带宽, 低延迟
- **网络接口**: 支持DPDK的网卡（可选，用于高性能）

#### 集群配置（大型部署）
- **管理节点**: 16C32G, 500GB SSD
- **工作节点**: 32C64G, 1TB NVMe SSD
- **存储节点**: 8C16G, 4TB HDD + 1TB SSD
- **监控节点**: 8C16G, 200GB SSD

### 系统要求

#### 操作系统

```bash
# Ubuntu/Debian (推荐)
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    git \
    curl \
    wget \
    htop \
    iotop \
    sysstat \
    nethogs \
    tcpdump \
    nginx \
    redis-server \
    postgresql \
    docker.io \
    docker-compose

# CentOS/RHEL
sudo yum groupinstall -y "Development Tools"
sudo yum install -y \
    cmake \
    pkgconfig \
    git \
    curl \
    wget \
    htop \
    iotop \
    sysstat \
    nethogs \
    tcpdump \
    nginx \
    redis \
    postgresql-server \
    docker
```

#### 网络配置

```bash
# 配置网络参数
cat >> /etc/sysctl.conf << EOF
# 网络性能优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.netdev_max_backlog = 5000

# 文件描述符限制
fs.file-max = 2097152

# 内存管理
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# 应用配置
sudo sysctl -p

# 配置用户限制
cat >> /etc/security/limits.conf << EOF
websec soft nofile 1048576
websec hard nofile 2097152
websec soft nproc 32768
websec hard nproc 65536
EOF
```

## 📦 **软件安装**

### 1. Rust工具链安装

```bash
# 安装Rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 安装稳定版本
rustup update stable
rustup default stable

# 验证安装
rustc --version
cargo --version
```

### 2. Intel Hyperscan安装

```bash
# 方法1: 从包管理器安装（快速）
# Ubuntu/Debian
sudo apt install -y libhyperscan-dev

# CentOS/RHEL
sudo yum install -y hyperscan-devel

# 方法2: 从源码编译（推荐，性能最佳）
cd /tmp
wget https://github.com/Intel/hyperscan/archive/v5.4.2.tar.gz
tar -xzf v5.4.2.tar.gz
cd hyperscan-5.4.2

# 安装依赖
sudo apt install -y ragel libboost-all-dev

# 配置编译（生产优化）
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/hyperscan \
      -DBUILD_SHARED_LIBS=ON \
      -DDBUILD_TOOLS=ON \
      -DENABLE_PCRE=ON \
      -DCMAKE_C_FLAGS="-O3 -march=native -mtune=native" \
      ..

# 并行编译
make -j$(nproc)

# 安装
sudo make install
sudo ldconfig

# 验证安装
pkg-config --modversion libhs
ls -la /opt/hyperscan/lib/libhs.so*
```

### 3. Web安全扫描系统安装

```bash
# 创建部署目录
sudo mkdir -p /opt/websecurity/{bin,lib,config,logs,run}
sudo useradd -r -s /bin/false websec
sudo chown -R websec:websec /opt/websecurity

# 克隆代码
cd /tmp
git clone https://github.com/your-org/web_scan_rust.git
cd web_scan_rust
git checkout v1.0.0

# 配置编译环境
export PKG_CONFIG_PATH="/opt/hyperscan/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/opt/hyperscan/lib:$LD_LIBRARY_PATH"

# 编译发布版本
cargo build --release --features hyperscan

# 验证编译
if [ $? -eq 0 ]; then
    echo "✅ 编译成功"
else
    echo "❌ 编译失败"
    exit 1
fi

# 安装库文件
sudo cp target/release/libweb_scan_rust.so /opt/websecurity/lib/
sudo cp target/release/web_scan_rust.h /opt/websecurity/include/

# 安装主程序
sudo cp target/release/web_scan_rust /opt/websecurity/bin/

# 设置权限
sudo chmod 755 /opt/websecurity/bin/*
sudo chmod 644 /opt/websecurity/lib/*
sudo chmod 644 /opt/websecurity/include/*

# 配置环境
echo 'export PKG_CONFIG_PATH="/opt/hyperscan/lib/pkgconfig:$PKG_CONFIG_PATH"' | sudo tee -a /etc/environment
echo 'export LD_LIBRARY_PATH="/opt/websecurity/lib:/opt/hyperscan/lib:$LD_LIBRARY_PATH"' | sudo tee -a /etc/environment

# 创建配置目录
sudo mkdir -p /opt/websecurity/config/{rules,policies,profiles}
```

## 🔧 **配置管理**

### 1. 主配置文件

```toml
# /opt/websecurity/config/security.toml

[engine]
# 引擎基本配置
enabled = true
max_sessions = 10000
session_timeout = 300  # 5分钟
worker_threads = 8

[hyperscan]
# Hyperscan加速配置
enabled = true
mode = "stream"  # stream/block
compile_threads = 4
database_cache_size = "2GB"

[performance]
# 性能优化配置
packet_buffer_size = "64MB"
max_packet_size = "1MB"
processing_timeout = 30  # 秒
batch_size = 1000

[logging]
# 日志配置
level = "info"  # debug, info, warn, error
file = "/opt/websecurity/logs/security.log"
max_file_size = "100MB"
max_files = 10
enable_syslog = true

[monitoring]
# 监控配置
enable_metrics = true
metrics_port = 9090
health_check_port = 8080
stats_update_interval = 10  # 秒

[api]
# API服务配置
enable_rest_api = true
rest_api_port = 8081
api_key_required = true
rate_limit = 1000  # requests/minute

[security]
# 安全配置
enable_input_validation = true
max_string_length = 1048576  # 1MB
enable_rate_limiting = true
max_requests_per_ip = 1000  # per minute
```

### 2. 规则配置文件

```json
// /opt/websecurity/config/rules/web_rules.json

{
  "metadata": {
    "version": "1.0.0",
    "description": "Web安全扫描规则集",
    "last_updated": "2025-11-27T16:30:00Z",
    "author": "Security Team"
  },
  "rules": [
    {
      "id": 1001,
      "action": "alert",
      "message": "SQL注入攻击检测",
      "pattern": "(?i)union\\s+(all\\s+)?select",
      "http_location": "any",
      "pcre": "(?i)union\\s+(all\\s+)?select\\s+.*\\s+from",
      "pcre_flags": "i",
      "metadata": {
        "category": "sql_injection",
        "severity": "critical",
        "reference": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
        "tags": ["sql", "injection", "union", "select"]
      }
    },
    {
      "id": 1002,
      "action": "drop",
      "message": "XSS攻击检测",
      "pattern": "<script",
      "http_location": "any",
      "pcre": "(?i)<script[^>]*>.*?</script>",
      "pcre_flags": "is",
      "metadata": {
        "category": "xss",
        "severity": "high",
        "reference": "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
        "tags": ["xss", "script", "javascript"]
      }
    },
    {
      "id": 1003,
      "action": "alert",
      "message": "路径遍历攻击",
      "pattern": "../",
      "http_location": "uri",
      "pcre": "(?i)\\.\\.[\\\\/]",
      "pcre_flags": "i",
      "metadata": {
        "category": "path_traversal",
        "severity": "medium",
        "reference": "https://owasp.org/www-project-top-ten/2017/A4_2017-Insecure_Direct_Object_References",
        "tags": ["path", "traversal", "directory"]
      }
    },
    {
      "id": 1004,
      "action": "reset",
      "message": "命令注入攻击",
      "pattern": "exec(",
      "http_location": "any",
      "pcre": "(?i)(exec\\(|system\\(|eval\\(|shell_exec\\()",
      "pcre_flags": "i",
      "metadata": {
        "category": "command_injection",
        "severity": "critical",
        "reference": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
        "tags": ["command", "injection", "exec", "shell"]
      }
    }
  ]
}
```

### 3. 环境变量配置

```bash
# /opt/websecurity/config/environment.sh

#!/bin/bash

# 核心环境变量
export WEBSERVER_HOME="/opt/websecurity"
export WEBSERVER_CONFIG="$WEBSERVER_HOME/config/security.toml"
export WEBSERVER_RULES="$WEBSERVER_HOME/config/rules"
export WEBSERVER_LOGS="$WEBSERVER_HOME/logs"

# Hyperscan环境
export PKG_CONFIG_PATH="/opt/hyperscan/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/opt/hyperscan/lib:$WEBSERVER_HOME/lib:$LD_LIBRARY_PATH"

# 性能环境变量
export RUST_LOG="info"
export RUST_BACKTRACE=1
export MALLOC_CONF="background_thread:true,metadata_thp:auto,dirty_decay_ms:1000,muzzy_decay_ms:1000"

# 监控环境变量
export PROMETHEUS_ENABLED="true"
export PROMETHEUS_PORT="9090"
export HEALTH_CHECK_PORT="8080"

# 安全环境变量
export API_KEY="your_secure_api_key_here"
export MAX_CONNECTIONS="10000"
export SESSION_TIMEOUT="300"

# 日志环境变量
export LOG_LEVEL="info"
export LOG_FORMAT="json"
export SYSLOG_ENABLED="true"
```

## 🚀 **服务部署**

### 1. Systemd服务配置

```ini
# /etc/systemd/system/websecurity.service

[Unit]
Description=Web Security Scanner Service
After=network.target network-online.target
Wants=network-online.target
Requires=network.target

[Service]
Type=simple
User=websec
Group=websec
WorkingDirectory=/opt/websecurity
Environment=LD_LIBRARY_PATH=/opt/hyperscan/lib:/opt/websecurity/lib
Environment=PKG_CONFIG_PATH=/opt/hyperscan/lib/pkgconfig
Environment=RUST_LOG=info
Environment=WEBSERVER_CONFIG=/opt/websecurity/config/security.toml

ExecStart=/opt/websecurity/bin/web_scan_rust --config $WEBSERVER_CONFIG
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=always
RestartSec=10
StartLimitBurst=5
StartLimitIntervalSec=60

# 安全设置
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/websecurity/logs
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
MemoryDenyWriteExecute=true

# 文件权限
UMask=0027

# 资源限制
LimitNOFILE=1048576
LimitNPROC=32768
LimitFSIZE=infinity

[Install]
WantedBy=multi-user.target
```

### 2. 服务管理脚本

```bash
#!/bin/bash
# /opt/websecurity/scripts/manage.sh

set -e

SERVICE_NAME="websecurity"
SERVICE_USER="websec"
SERVICE_HOME="/opt/websecurity"
SERVICE_CONFIG="$SERVICE_HOME/config/security.toml"

# 检查服务状态
check_status() {
    echo "📋 检查服务状态..."
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "✅ 服务运行中"
        systemctl status $SERVICE_NAME --no-pager
    else
        echo "❌ 服务未运行"
        systemctl status $SERVICE_NAME --no-pager
    fi
}

# 启动服务
start_service() {
    echo "🚀 启动Web安全扫描服务..."

    # 检查配置文件
    if [ ! -f "$SERVICE_CONFIG" ]; then
        echo "❌ 配置文件不存在: $SERVICE_CONFIG"
        exit 1
    fi

    # 启动服务
    systemctl start $SERVICE_NAME

    # 等待服务启动
    sleep 5

    # 验证服务状态
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "✅ 服务启动成功"
        check_status
    else
        echo "❌ 服务启动失败"
        journalctl -u $SERVICE_NAME -n 50 --no-pager
        exit 1
    fi
}

# 停止服务
stop_service() {
    echo "🛑 停止Web安全扫描服务..."

    # 停止服务
    systemctl stop $SERVICE_NAME

    # 等待服务停止
    sleep 3

    # 验证服务状态
    if systemctl is-active --quiet $SERVICE_NAME; then
        echo "❌ 服务停止失败"
        systemctl kill $SERVICE_NAME
        sleep 2
    else
        echo "✅ 服务停止成功"
    fi
}

# 重启服务
restart_service() {
    echo "🔄 重启Web安全扫描服务..."
    stop_service
    start_service
}

# 重新加载配置
reload_service() {
    echo "🔄 重新加载配置..."

    # 验证配置文件语法
    if ! /opt/websecurity/bin/web_scan_rust --config-check "$SERVICE_CONFIG"; then
        echo "❌ 配置文件验证失败"
        exit 1
    fi

    # 重新加载服务
    systemctl reload $SERVICE_NAME

    if [ $? -eq 0 ]; then
        echo "✅ 配置重新加载成功"
    else
        echo "❌ 配置重新加载失败"
        journalctl -u $SERVICE_NAME -n 20 --no-pager
        exit 1
    fi
}

# 查看日志
view_logs() {
    echo "📝 查看服务日志..."

    # 系统日志
    echo "=== 系统日志 ==="
    journalctl -u $SERVICE_NAME -f --no-pager

    # 应用日志
    echo "=== 应用日志 ==="
    tail -f $SERVICE_HOME/logs/security.log
}

# 性能监控
monitor_performance() {
    echo "📊 性能监控..."

    # CPU和内存使用
    echo "=== 系统资源 ==="
    top -bn1 -u $SERVICE_USER | head -20

    # 网络连接
    echo "=== 网络连接 ==="
    netstat -an | grep :8080 | wc -l
    netstat -an | grep ESTABLISHED | wc -l

    # 进程信息
    echo "=== 进程信息 ==="
    ps aux | grep web_scan_rust | grep -v grep

    # 服务统计
    if pgrep -f web_scan_rust > /dev/null; then
        echo "=== 服务统计 ==="
        curl -s http://localhost:9090/metrics | grep -E "(websec_packets_processed|websec_packets_matched)" || \
            echo "指标服务不可用"
    fi
}

# 健康检查
health_check() {
    echo "🏥 健康检查..."

    # 服务状态检查
    if ! systemctl is-active --quiet $SERVICE_NAME; then
        echo "❌ 服务未运行"
        return 1
    fi

    # 端口监听检查
    if ! netstat -an | grep -q ":8080.*LISTEN"; then
        echo "❌ 端口8080未监听"
        return 1
    fi

    if ! netstat -an | grep -q ":9090.*LISTEN"; then
        echo "❌ 端口9090未监听"
        return 1
    fi

    # API健康检查
    if ! curl -s -f http://localhost:8080/health > /dev/null; then
        echo "❌ 健康检查API不可用"
        return 1
    fi

    # 规则加载检查
    if [ ! -f "$SERVICE_HOME/config/rules/web_rules.json" ]; then
        echo "❌ 规则文件不存在"
        return 1
    fi

    echo "✅ 所有健康检查通过"
    return 0
}

# 主函数
main() {
    case "$1" in
        "start")
            start_service
            ;;
        "stop")
            stop_service
            ;;
        "restart")
            restart_service
            ;;
        "reload")
            reload_service
            ;;
        "status")
            check_status
            ;;
        "logs")
            view_logs
            ;;
        "monitor")
            monitor_performance
            ;;
        "health")
            health_check
            ;;
        "help"|*)
            echo "用法: $0 {start|stop|restart|reload|status|logs|monitor|health|help}"
            echo ""
            echo "命令说明:"
            echo "  start   - 启动服务"
            echo "  stop    - 停止服务"
            echo "  restart - 重启服务"
            echo "  reload  - 重新加载配置"
            echo "  status  - 查看服务状态"
            echo "  logs    - 查看服务日志"
            echo "  monitor - 性能监控"
            echo "  health  - 健康检查"
            echo "  help    - 显示帮助信息"
            exit 1
            ;;
    esac
}

main "$@"
```

### 3. 负载均衡器配置

```nginx
# /etc/nginx/sites-available/websecurity

upstream websecurity_backend {
    least_conn;
    server 192.168.1.10:8080 max_fails=3 fail_timeout=30s;
    server 192.168.1.11:8080 max_fails=3 fail_timeout=30s backup;
    server 192.168.1.12:8080 max_fails=3 fail_timeout=30s backup;

    # 健康检查
    keepalive 32;
}

# HTTP API服务器
server {
    listen 80;
    server_name security-api.example.com;

    # 安全头部
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # 限速配置
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

    location / {
        limit_req zone=api burst=20 nodelay;

        proxy_pass http://websecurity_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 超时设置
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;

        # 缓冲设置
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # 健康检查端点
    location /health {
        access_log off;
        proxy_pass http://websecurity_backend/health;
    }

    # 监控指标端点
    location /metrics {
        allow 127.0.0.1;
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://websecurity_backend/metrics;
    }
}

# WebSocket服务器（用于实时监控）
server {
    listen 8081;
    server_name security-ws.example.com;

    location /ws {
        proxy_pass http://websecurity_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
```

## 🐳 **Docker容器化**

### 1. Dockerfile

```dockerfile
# Dockerfile
FROM ubuntu:22.04

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:/usr/local/rustup/bin:$PATH
ENV WEBSERVER_HOME=/opt/websecurity
ENV PKG_CONFIG_PATH=/opt/hyperscan/lib/pkgconfig
ENV LD_LIBRARY_PATH=/opt/hyperscan/lib:/opt/websecurity/lib

# 安装系统依赖
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    git \
    curl \
    wget \
    ca-certificates \
    libssl-dev \
    pkg-config \
    ragel \
    libboost-all-dev

# 安装Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN rustup default stable

# 安装Hyperscan
WORKDIR /tmp
RUN wget https://github.com/Intel/hyperscan/archive/v5.4.2.tar.gz && \
    tar -xzf v5.4.2.tar.gz && \
    cd hyperscan-5.4.2 && \
    mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX=/opt/hyperscan \
          -DBUILD_SHARED_LIBS=ON \
          -DDBUILD_TOOLS=ON \
          -DENABLE_PCRE=ON \
          .. && \
    make -j$(nproc) && \
    make install

# 创建应用用户
RUN useradd -m -u 1000 websec && \
    mkdir -p $WEBSERVER_HOME/{bin,lib,config,logs} && \
    chown -R websec:websec $WEBSERVER_HOME

# 复制源代码
COPY . /tmp/websecurity/
WORKDIR /tmp/websecurity

# 编译应用
RUN cargo build --release --features hyperscan

# 安装应用
RUN cp target/release/libweb_scan_rust.so $WEBSERVER_HOME/lib/ && \
    cp target/release/web_scan_rust $WEBSERVER_HOME/bin/ && \
    cp -r config $WEBSERVER_HOME/ && \
    chown -R websec:websec $WEBSERVER_HOME

# 切换到应用用户
USER websec
WORKDIR $WEBSERVER_HOME

# 暴露端口
EXPOSE 8080 9090

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# 启动命令
CMD ["./bin/web_scan_rust", "--config", "config/security.toml"]
```

### 2. Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  websecurity:
    build: .
    container_name: websecurity
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./config:/opt/websecurity/config:ro
      - ./logs:/opt/websecurity/logs
      - ./data:/opt/websecurity/data
    environment:
      - RUST_LOG=info
      - WEBSERVER_CONFIG=/opt/websecurity/config/security.toml
      - LD_LIBRARY_PATH=/opt/hyperscan/lib:/opt/websecurity/lib
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - websecurity-network

  redis:
    image: redis:7-alpine
    container_name: websecurity-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes
    networks:
      - websecurity-network

  postgres:
    image: postgres:14-alpine
    container_name: websecurity-postgres
    restart: unless-stopped
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_DB=websecurity
      - POSTGRES_USER=websec
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./sql:/docker-entrypoint-initdb.d
    networks:
      - websecurity-network

  prometheus:
    image: prom/prometheus:latest
    container_name: websecurity-prometheus
    restart: unless-stopped
    ports:
      - "9091:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    networks:
      - websecurity-network

  grafana:
    image: grafana/grafana:latest
    container_name: websecurity-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources
    networks:
      - websecurity-network

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: websecurity-elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    networks:
      - websecurity-network

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: websecurity-kibana
    restart: unless-stopped
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch
    networks:
      - websecurity-network

volumes:
  redis-data:
  postgres-data:
  prometheus-data:
  grafana-data:
  elasticsearch-data:

networks:
  websecurity-network:
    driver: bridge
```

### 3. 部署脚本

```bash
#!/bin/bash
# deploy.sh

set -e

PROJECT_NAME="websecurity"
DOCKER_COMPOSE_FILE="docker-compose.yml"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 检查Docker环境
check_docker() {
    print_status "检查Docker环境..."

    if ! command -v docker &> /dev/null; then
        print_error "Docker未安装，请先安装Docker"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose未安装，请先安装Docker Compose"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        print_error "Docker服务未运行，请启动Docker服务"
        exit 1
    fi

    print_status "Docker环境检查通过"
}

# 准备配置文件
prepare_configs() {
    print_status "准备配置文件..."

    # 创建配置目录
    mkdir -p config/{rules,policies,profiles}
    mkdir -p logs
    mkdir -p data
    mkdir -p monitoring/{prometheus,grafana/{dashboards,datasources}}
    mkdir -p sql

    # 复制默认配置
    if [ ! -f config/security.toml ]; then
        cp config/security.toml.example config/security.toml
        print_warning "已创建默认配置文件，请根据需要修改 config/security.toml"
    fi

    # 复制规则文件
    if [ ! -f config/rules/web_rules.json ]; then
        cp config/rules/web_rules.json.example config/rules/web_rules.json
    fi

    # 创建Prometheus配置
    cat > monitoring/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'websecurity'
    static_configs:
      - targets: ['websecurity:9090']
    metrics_path: /metrics
    scrape_interval: 5s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
EOF

    print_status "配置文件准备完成"
}

# 构建Docker镜像
build_image() {
    print_status "构建Docker镜像..."

    docker build -t $PROJECT_NAME .

    print_status "Docker镜像构建完成"
}

# 启动服务
start_services() {
    print_status "启动Web安全扫描服务..."

    docker-compose -f $DOCKER_COMPOSE_FILE up -d

    # 等待服务启动
    print_status "等待服务启动..."
    sleep 30

    # 检查服务状态
    if docker-compose -f $DOCKER_COMPOSE_FILE ps | grep -q "Up"; then
        print_status "服务启动成功"
        docker-compose -f $DOCKER_COMPOSE_FILE ps
    else
        print_error "服务启动失败"
        docker-compose -f $DOCKER_COMPOSE_FILE logs
        exit 1
    fi
}

# 健康检查
health_check() {
    print_status "执行健康检查..."

    # 检查主服务
    if curl -f -s http://localhost:8080/health > /dev/null; then
        print_status "主服务健康检查通过"
    else
        print_error "主服务健康检查失败"
        return 1
    fi

    # 检查指标服务
    if curl -f -s http://localhost:9090/metrics > /dev/null; then
        print_status "指标服务健康检查通过"
    else
        print_error "指标服务健康检查失败"
        return 1
    fi

    # 检查数据库连接
    if docker exec websecurity-postgres pg_isready -U websec > /dev/null; then
        print_status "PostgreSQL连接检查通过"
    else
        print_warning "PostgreSQL连接检查失败"
    fi

    # 检查Redis连接
    if docker exec websecurity-redis redis-cli ping > /dev/null; then
        print_status "Redis连接检查通过"
    else
        print_warning "Redis连接检查失败"
    fi

    print_status "所有健康检查完成"
    return 0
}

# 显示部署信息
show_deployment_info() {
    print_status "部署完成！"
    echo ""
    echo "📊 访问地址："
    echo "  Web安全API:      http://localhost:8080"
    echo "  健康检查:        http://localhost:8080/health"
    echo "  监控指标:        http://localhost:9090/metrics"
    echo "  Prometheus:      http://localhost:9091"
    echo "  Grafana:         http://localhost:3000 (admin/admin)"
    echo "  Kibana:          http://localhost:5601"
    echo ""
    echo "📝 日志查看："
    echo "  docker-compose -f $DOCKER_COMPOSE_FILE logs -f websecurity"
    echo ""
    echo "🛠️  管理命令："
    echo "  停止服务:        docker-compose -f $DOCKER_COMPOSE_FILE down"
    echo "  重启服务:        docker-compose -f $DOCKER_COMPOSE_FILE restart"
    echo "  查看状态:        docker-compose -f $DOCKER_COMPOSE_FILE ps"
    echo "  扩展实例:        docker-compose -f $DOCKER_COMPOSE_FILE up -d --scale websecurity=3"
}

# 主函数
main() {
    case "$1" in
        "deploy")
            check_docker
            prepare_configs
            build_image
            start_services
            sleep 10
            health_check
            show_deployment_info
            ;;
        "stop")
            docker-compose -f $DOCKER_COMPOSE_FILE down
            print_status "服务已停止"
            ;;
        "restart")
            docker-compose -f $DOCKER_COMPOSE_FILE restart
            print_status "服务已重启"
            ;;
        "logs")
            docker-compose -f $DOCKER_COMPOSE_FILE logs -f websecurity
            ;;
        "status")
            docker-compose -f $DOCKER_COMPOSE_FILE ps
            ;;
        "health")
            health_check
            ;;
        "clean")
            docker-compose -f $DOCKER_COMPOSE_FILE down -v
            docker system prune -f
            print_status "清理完成"
            ;;
        "help"|*)
            echo "用法: $0 {deploy|stop|restart|logs|status|health|clean|help}"
            echo ""
            echo "命令说明:"
            echo "  deploy  - 完整部署服务"
            echo "  stop    - 停止所有服务"
            echo "  restart - 重启所有服务"
            echo "  logs    - 查看服务日志"
            echo "  status  - 查看服务状态"
            echo "  health  - 执行健康检查"
            echo "  clean   - 清理所有容器和卷"
            echo "  help    - 显示帮助信息"
            exit 1
            ;;
    esac
}

main "$@"
```

## ☸️ **Kubernetes部署**

### 1. Kubernetes清单

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: websecurity
  labels:
    name: websecurity
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: websecurity-config
  namespace: websecurity
data:
  security.toml: |
    [engine]
    enabled = true
    max_sessions = 10000
    session_timeout = 300
    worker_threads = 8

    [hyperscan]
    enabled = true
    mode = "stream"
    compile_threads = 4
    database_cache_size = "2GB"

    [performance]
    packet_buffer_size = "64MB"
    max_packet_size = "1MB"
    processing_timeout = 30
    batch_size = 1000

    [logging]
    level = "info"
    enable_syslog = true

    [monitoring]
    enable_metrics = true
    metrics_port = 9090
    health_check_port = 8080
---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: websecurity-secrets
  namespace: websecurity
type: Opaque
data:
  api-key: eW91cl9fc2VjdXJlX2FwaV9fa2V5X2E=
  database-password: c2VjdXJlUGBhc3N3b3Jk
---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: websecurity
  namespace: websecurity
  labels:
    app: websecurity
spec:
  replicas: 3
  selector:
    matchLabels:
      app: websecurity
  template:
    metadata:
      labels:
        app: websecurity
    spec:
      containers:
      - name: websecurity
        image: websecurity:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        env:
        - name: WEBSERVER_CONFIG
          value: "/etc/websecurity/security.toml"
        - name: LD_LIBRARY_PATH
          value: "/opt/hyperscan/lib:/opt/websecurity/lib"
        - name: RUST_LOG
          value: "info"
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: websecurity-secrets
              key: api-key
        volumeMounts:
        - name: config
          mountPath: /etc/websecurity
          readOnly: true
        - name: logs
          mountPath: /opt/websecurity/logs
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: websecurity-config
      - name: logs
        emptyDir: {}
---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: websecurity-service
  namespace: websecurity
spec:
  selector:
    app: websecurity
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
  type: ClusterIP
---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: websecurity-ingress
  namespace: websecurity
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - security-api.example.com
    secretName: websecurity-tls
  rules:
  - host: security-api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: websecurity-service
            port:
              number: 80
---
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: websecurity-hpa
  namespace: websecurity
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: websecurity
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### 2. 部署脚本

```bash
#!/bin/bash
# k8s-deploy.sh

set -e

NAMESPACE="websecurity"
KUBECTL="kubectl"

# 颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# 检查Kubernetes环境
check_k8s() {
    print_status "检查Kubernetes环境..."

    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl未安装，请先安装kubectl"
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        print_error "无法连接到Kubernetes集群"
        exit 1
    fi

    print_status "Kubernetes环境检查通过"
}

# 创建命名空间
create_namespace() {
    print_status "创建命名空间..."

    $KUBECTL apply -f k8s/namespace.yaml

    print_status "命名空间创建完成"
}

# 部署配置和密钥
deploy_configs() {
    print_status "部署配置和密钥..."

    $KUBECTL apply -f k8s/configmap.yaml
    $KUBECTL apply -f k8s/secret.yaml

    print_status "配置和密钥部署完成"
}

# 部署应用
deploy_application() {
    print_status "部署Web安全扫描应用..."

    $KUBECTL apply -f k8s/deployment.yaml
    $KUBECTL apply -f k8s/service.yaml

    # 等待部署完成
    $KUBECTL rollout status deployment/websecurity -n $NAMESPACE --timeout=300s

    print_status "应用部署完成"
}

# 配置Ingress
setup_ingress() {
    print_status "配置Ingress..."

    $KUBECTL apply -f k8s/ingress.yaml

    print_status "Ingress配置完成"
}

# 配置自动扩缩容
setup_hpa() {
    print_status "配置自动扩缩容..."

    $KUBECTL apply -f k8s/hpa.yaml

    print_status "自动扩缩容配置完成"
}

# 验证部署
verify_deployment() {
    print_status "验证部署..."

    # 检查Pod状态
    $KUBECTL get pods -n $NAMESPACE -l app=websecurity

    # 等待所有Pod就绪
    for i in {1..30}; do
        ready_count=$($KUBECTL get pods -n $NAMESPACE -l app=websecurity -o jsonpath='{.items[*].status.containerStatuses[0].ready}' | grep -c true || echo 0)
        total_count=$($KUBECTL get pods -n $NAMESPACE -l app=websecurity --no-headers | wc -l)

        if [ "$ready_count" -eq "$total_count" ] && [ "$ready_count" -gt 0 ]; then
            print_status "所有Pod已就绪 ($ready_count/$total_count)"
            break
        fi

        print_warning "等待Pod就绪... ($ready_count/$total_count)"
        sleep 10
    done

    # 检查服务
    $KUBECTL get svc -n $NAMESPACE

    # 检查Ingress
    $KUBECTL get ingress -n $NAMESPACE

    # 执行健康检查
    pod_ip=$($KUBECTL get pods -n $NAMESPACE -l app=websecurity -o jsonpath='{.items[0].status.podIP}')
    if [ -n "$pod_ip" ]; then
        if curl -f -s "http://$pod_ip/health" > /dev/null; then
            print_status "健康检查通过"
        else
            print_error "健康检查失败"
        fi
    fi

    print_status "部署验证完成"
}

# 显示部署信息
show_deployment_info() {
    print_status "Kubernetes部署完成！"
    echo ""
    echo "📊 访问信息："
    echo "  命名空间:        $NAMESPACE"
    echo "  Pod数量:          $($KUBECTL get pods -n $NAMESPACE -l app=websecurity --no-headers | wc -l)"
    echo "  服务名称:        websecurity-service"
    echo "  内部服务IP:      $($KUBECTL get svc websecurity-service -n $NAMESPACE -o jsonpath='{.spec.clusterIP}')"
    echo "  外部访问URL:    http://security-api.example.com"
    echo ""
    echo "🛠️ 管理命令："
    echo "  查看Pod:          kubectl get pods -n $NAMESPACE"
    echo "  查看日志:          kubectl logs -f deployment/websecurity -n $NAMESPACE"
    echo "  扩容:              kubectl scale deployment websecurity --replicas=5 -n $NAMESPACE"
    echo "  更新配置:          kubectl apply -f k8s/ -n $NAMESPACE"
    echo "  删除部署:          kubectl delete namespace $NAMESPACE"
}

# 主函数
main() {
    case "$1" in
        "deploy")
            check_k8s
            create_namespace
            deploy_configs
            deploy_application
            setup_ingress
            setup_hpa
            verify_deployment
            show_deployment_info
            ;;
        "delete")
            print_status "删除Kubernetes部署..."
            $KUBECTL delete namespace $NAMESPACE
            print_status "部署已删除"
            ;;
        "status")
            $KUBECTL get pods,svc,hpa,ingress -n $NAMESPACE
            ;;
        "logs")
            $KUBECTL logs -f deployment/websecurity -n $NAMESPACE
            ;;
        "scale")
            if [ -z "$2" ]; then
                echo "请指定副本数量: $0 scale <replicas>"
                exit 1
            fi
            $KUBECTL scale deployment websecurity --replicas=$2 -n $NAMESPACE
            print_status "扩容到 $2 个副本"
            ;;
        "update")
            print_status "更新应用配置..."
            $KUBECTL apply -f k8s/ -n $NAMESPACE
            $KUBECTL rollout restart deployment/websecurity -n $NAMESPACE
            print_status "配置更新完成"
            ;;
        "help"|*)
            echo "用法: $0 {deploy|delete|status|logs|scale <replicas>|update|help}"
            echo ""
            echo "命令说明:"
            echo "  deploy  - 完整部署到Kubernetes"
            echo "  delete  - 删除所有Kubernetes资源"
            echo "  status  - 查看部署状态"
            echo "  logs    - 查看应用日志"
            echo "  scale   - 扩容应用实例"
            echo "  update  - 更新应用配置"
            echo "  help    - 显示帮助信息"
            exit 1
            ;;
    esac
}

main "$@"
```

## 📊 **监控配置**

### 1. Prometheus配置

```yaml
# monitoring/prometheus.yml

global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'websecurity-prod'
    replica: '1'

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  # Web安全扫描服务
  - job_name: 'websecurity'
    static_configs:
      - targets:
        - 'websecurity-1:9090'
        - 'websecurity-2:9090'
        - 'websecurity-3:9090'
    metrics_path: /metrics
    scrape_interval: 5s
    scrape_timeout: 10s
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        replacement: '${1}'
        regex: '(.*):9090'

  # 节点监控
  - job_name: 'node-exporter'
    static_configs:
      - targets:
        - 'websecurity-1:9100'
        - 'websecurity-2:9100'
        - 'websecurity-3:9100'

  # 系统监控
  - job_name: 'systemd-exporter'
    static_configs:
      - targets:
        - 'websecurity-1:9555'
        - 'websecurity-2:9555'
        - 'websecurity-3:9555'

  # 数据库监控
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']

  # Redis监控
  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']

  # 负载均衡器监控
  - job_name: 'nginx-exporter'
    static_configs:
      - targets: ['nginx-exporter:9113']
```

### 2. 告警规则

```yaml
# monitoring/alert_rules.yml

groups:
- name: websecurity.rules
  rules:
  # 服务可用性告警
  - alert: WebSecurityServiceDown
    expr: up{job="websecurity"} == 0
    for: 1m
    labels:
      severity: critical
      service: websecurity
    annotations:
      summary: "Web安全扫描服务不可用"
      description: "Web安全扫描服务 {{ $labels.instance }} 已停止响应超过1分钟"

  # 高CPU使用率告警
  - alert: HighCPUUsage
    expr: rate(cpu_usage_total{job="node-exporter"}[5m]) > 0.8
    for: 5m
    labels:
      severity: warning
      service: websecurity
    annotations:
      summary: "CPU使用率过高"
      description: "节点 {{ $labels.instance }} CPU使用率超过80%持续5分钟"

  # 高内存使用率告警
  - alert: HighMemoryUsage
    expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.9
    for: 5m
    labels:
      severity: warning
      service: websecurity
    annotations:
      summary: "内存使用率过高"
      description: "节点 {{ $labels.instance }} 内存使用率超过90%持续5分钟"

  # 威胁检测率异常告警
  - alert: HighThreatDetectionRate
    expr: rate(websec_packets_matched_total[5m]) / rate(websec_packets_processed_total[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
      service: websecurity
    annotations:
      summary: "威胁检测率异常"
      description: "威胁检测率超过10%持续2分钟，可能存在攻击活动"

  # 大量连接告警
  - alert: HighConnectionCount
    expr: websec_sessions_active > 8000
    for: 1m
    labels:
      severity: warning
      service: websecurity
    annotations:
      summary: "活跃连接数过高"
      description: "活跃会话数超过8000，可能存在DDoS攻击"

  # 规则匹配失败告警
  - alert: RuleMatchFailure
    expr: rate(websec_rule_match_errors_total[5m]) > 10
    for: 1m
    labels:
      severity: error
      service: websecurity
    annotations:
      summary: "规则匹配失败率过高"
      description: "规则匹配错误率超过10次/分钟，请检查规则配置"
```

### 3. Grafana仪表板

```json
{
  "dashboard": {
    "id": null,
    "title": "Web安全扫描监控",
    "tags": ["websecurity", "security", "monitoring"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "实时威胁检测",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(websec_packets_matched_total[1m])",
            "refId": "A",
            "legendFormat": "威胁/分钟"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "reqps",
            "thresholds": {
              "steps": [
                {"color": "green", "value": null},
                {"color": "yellow", "value": 10},
                {"color": "red", "value": 50}
              ]
            }
          }
        },
        "options": {
          "reduceOptions": ["mean"],
          "calcs": ["mean"],
          "orientation": "horizontal",
          "textMode": "auto",
          "colorMode": "value",
          "graphMode": "area",
          "justifyMode": "auto",
          "text": {},
          "pluginVersion": "6.2.5"
        },
        "gridPos": {
          "h": 4,
          "w": 6,
          "x": 0,
          "y": 0
        }
      },
      {
        "id": 2,
        "title": "处理性能",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(websec_packets_processed_total[1m])",
            "refId": "B",
            "legendFormat": "处理速率"
          },
          {
            "expr": "rate(websec_packets_matched_total[1m])",
            "refId": "C",
            "legendFormat": "匹配速率"
          }
        ],
        "yAxes": [
          {
            "label": "包/秒",
            "show": true
          }
        ],
        "gridPos": {
          "h": 8,
          "w": 12,
          "x": 6,
          "y": 0
        }
      }
    ]
  }
}
```

## 🛡️ **安全配置**

### 1. 防火墙配置

```bash
# iptables规则
#!/bin/bash

# 清除现有规则
iptables -F
iptables -X

# 设置默认策略
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# 允许本地回环
iptables -A INPUT -i lo -j ACCEPT

# 允许已建立的连接
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH访问（仅限管理网段）
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT

# HTTP/HTTPS访问
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# API访问（限制IP范围）
iptables -A INPUT -p tcp --dport 8080 -s 10.0.0.0/8 -j ACCEPT

# 监控端口（仅本地访问）
iptables -A INPUT -p tcp --dport 9090 -s 127.0.0.1/8 -j ACCEPT

# 防止DDoS攻击
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 100 -j DROP
iptables -A INPUT -p tcp --dport 8080 -m connlimit --connlimit-above 50 -j DROP

# 防止端口扫描
iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
iptables -A INPUT -m recent --name portscan --set --name portscan -p tcp --dport 80 -j DROP

# 保存规则
iptables-save > /etc/iptables/rules.v4
```

### 2. 访问控制配置

```bash
# nginx访问控制
server {
    # 基础安全配置
    server_tokens off;
    more_clear_headers Server;

    # 限制请求大小
    client_max_body_size 10M;

    # 限制请求方法
    if ($request_method !~ ^(GET|POST|HEAD|PUT|DELETE|OPTIONS)$ ) {
        return 405;
    }

    # 防止恶意User-Agent
    if ($http_user_agent ~* (bot|crawl|spider|scraper)$ ) {
        return 403;
    }

    # 限制请求速率
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=general:10m rate=5r/s;

    # 应用限速
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://websecurity_backend;
    }

    location / {
        limit_req zone=general burst=10 nodelay;
        proxy_pass http://websecurity_backend;
    }
}
```

### 3. SSL/TLS配置

```bash
# 生成自签名证书（开发环境）
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/websecurity.key \
    -out /etc/ssl/certs/websecurity.crt \
    -subj "/C=CN/ST=State/L=City/O=Organization/CN=websecurity.example.com"

# 生产环境建议使用Let's Encrypt
certbot certonly --webroot -w /var/www/html \
    -d security-api.example.com
```

## 📈 **性能调优**

### 1. 系统级优化

```bash
# /etc/sysctl.d/99-websecurity.conf

# 网络优化
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.netdev_max_backlog = 10000

# 文件系统优化
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288

# 内存管理
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.dirty_expire_centisecs = 500
vm.dirty_writeback_centisecs = 100

# 进程管理
kernel.pid_max = 4194303
kernel.threads-max = 4194303
```

### 2. 应用级优化

```toml
# 性能优化配置
[engine]
worker_threads = 0  # 自动检测CPU核心数
max_sessions = 50000
session_timeout = 300
batch_size = 5000

[hyperscan]
compile_threads = 0  # 自动检测
database_cache_size = "4GB"
stream_buffer_size = "64MB"

[performance]
packet_buffer_size = "128MB"
max_packet_size = "2MB"
processing_timeout = 60
enable_batching = true
batch_timeout = 10ms

[caching]
enable_rule_cache = true
rule_cache_size = "1GB"
enable_session_cache = true
session_cache_ttl = 3600
```

### 3. JVM/编译器优化

```bash
# Rust编译优化
export RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C target-feature=+avx2"

# 内存分配器优化
export MALLOC_CONF="background_thread:true,metadata_thp:auto,dirty_decay_ms:1000"

# 数据库连接池优化
export DB_POOL_SIZE=20
export DB_CONNECTION_TIMEOUT=30
export DB_QUERY_TIMEOUT=60
```

## 📋 **部署验证**

### 1. 部署检查清单

```bash
#!/bin/bash
# deployment-checklist.sh

echo "🔍 Web安全扫描系统部署检查清单"
echo "=================================="

# 1. 系统环境检查
echo -e "\n1. 系统环境检查"
echo "  操作系统: $(uname -s) $(uname -r)"
echo "  内核版本: $(uname -v)"
echo "  CPU核心: $(nproc)"
echo "  内存大小: $(free -h | grep '^Mem:' | awk '{print $2}')"
echo "  存储空间: $(df -h / | tail -1 | awk '{print $4}')"

# 2. 服务状态检查
echo -e "\n2. 服务状态检查"
services=("websecurity" "nginx" "redis" "postgresql" "prometheus")
for service in "${services[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "  ✅ $service: 运行中"
    else
        echo "  ❌ $service: 未运行"
    fi
done

# 3. 端口监听检查
echo -e "\n3. 端口监听检查"
ports=("80" "443" "8080" "9090" "5432" "6379")
for port in "${ports[@]}"; do
    if netstat -an | grep -q ":$port.*LISTEN"; then
        echo "  ✅ 端口 $port: 监听中"
    else
        echo "  ❌ 端口 $port: 未监听"
    fi
done

# 4. 配置文件检查
echo -e "\n4. 配置文件检查"
config_files=(
    "/opt/websecurity/config/security.toml"
    "/opt/websecurity/config/rules/web_rules.json"
    "/etc/nginx/sites-available/websecurity"
    "/etc/monitoring/prometheus.yml"
)
for config in "${config_files[@]}"; do
    if [ -f "$config" ]; then
        echo "  ✅ $(basename $config): 存在"
    else
        echo "  ❌ $(basename $config): 不存在"
    fi
done

# 5. 权限检查
echo -e "\n5. 权限检查"
if [ "$(stat -c %U /opt/websecurity)" = "websec" ]; then
    echo "  ✅ 应用目录权限正确"
else
    echo "  ❌ 应用目录权限错误"
fi

# 6. 网络连通性检查
echo -e "\n6. 网络连通性检查"
if ping -c 1 8.8.8.8 > /dev/null 2>&1; then
    echo "  ✅ 外网连通: 正常"
else
    echo "  ❌ 外网连通: 异常"
fi

# 7. 磁盘空间检查
echo -e "\n7. 磁盘空间检查"
disk_usage=$(df /opt/websecurity | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "${disk_usage%}" -lt "80" ]; then
    echo "  ✅ 磁盘空间: 充足 (${disk_usage}%)"
else
    echo "  ⚠️  磁盘空间: 不足 (${disk_usage}%)"
fi

# 8. 负载检查
echo -e "\n8. 系统负载检查"
load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
cpu_cores=$(nproc)
if (( $(echo "$load_avg < $cpu_cores" | bc -l) )); then
    echo "  ✅ 系统负载: 正常 (${load_avg}/${cpu_cores})"
else
    echo "  ⚠️  系统负载: 过高 (${load_avg}/${cpu_cores})"
fi

# 9. 服务健康检查
echo -e "\n9. 服务健康检查"
if curl -f -s http://localhost:8080/health > /dev/null; then
    echo "  ✅ API健康检查: 通过"
else
    echo "  ❌ API健康检查: 失败"
fi

# 10. 日志错误检查
echo -e "\n10. 日志错误检查"
error_count=$(journalctl -u websecurity --since "1 hour ago" | grep -i error | wc -l)
if [ "$error_count" -eq 0 ]; then
    echo "  ✅ 最近1小时错误数: 0"
else
    echo "  ⚠️  最近1小时错误数: $error_count"
fi

echo -e "\n部署检查完成！"
```

### 2. 性能基准测试

```bash
#!/bin/bash
# performance-benchmark.sh

echo "🚀 Web安全扫描系统性能基准测试"
echo "======================================"

# 测试参数
CONCURRENT_CONNECTIONS=1000
TEST_DURATION=60
API_ENDPOINT="http://localhost:8080"

# 1. 吞吐量测试
echo -e "\n1. 吞吐量测试"
echo "测试参数: $CONCURRENT_CONNECTIONS 并发连接, $TEST_DURATION 秒"

# 使用ab进行基准测试
if command -v ab &> /dev/null; then
    ab -n $((CONCURRENT_CONNECTIONS * 100)) \
       -c $CONCURRENT_CONNECTIONS \
       -t $TEST_DURATION \
       "$API_ENDPOINT/health"
else
    echo "Apache Bench (ab) 未安装，跳过吞吐量测试"
fi

# 2. 内存使用测试
echo -e "\n2. 内存使用监控"
pid=$(pgrep -f web_scan_rust)
if [ -n "$pid" ]; then
    echo "进程ID: $pid"
    ps -p $pid -o pid,ppid,cmd,etime,pcpu,pmem,rss,vsz
else
    echo "Web安全扫描服务未运行"
fi

# 3. CPU使用率监控
echo -e "\n3. CPU使用率监控"
for i in {1..5}; do
    cpu_usage=$(top -bn1 -p $(pgrep -f web_scan_rust) | tail -1 | awk '{print $9}')
    echo "第 $i 次采样: CPU使用率 $cpu_usage%"
    sleep 2
done

# 4. 网络延迟测试
echo -e "\n4. 网络延迟测试"
for i in {1..10}; do
    latency=$(curl -o /dev/null -s -w "%{time_total}" "$API_ENDPOINT/health")
    echo "请求 $i: ${latency}s"
done

echo -e "\n性能基准测试完成！"
```

## 🎯 **部署完成总结**

通过本部署指南，您应该能够：

1. ✅ **成功部署** Web安全扫描系统到生产环境
2. ✅ **配置监控** 完整的监控和告警系统
3. ✅ **优化性能** 系统级和应用级的性能调优
4. ✅ **保障安全** 全面的安全配置和访问控制
5. ✅ **验证部署** 完整的部署验证和性能测试

### 📊 **生产环境特性**

- **高可用性**: 集群部署 + 自动故障转移
- **可扩展性**: 水平扩展 + 自动伸缩
- **监控告警**: 实时监控 + 智能告警
- **性能优化**: 多层优化 + 资源管理
- **安全防护**: 多层安全 + 访问控制
- **日志审计**: 完整日志 + 长期存储

### 🚀 **下一步建议**

1. **监控优化**: 根据实际业务调整监控指标
2. **容量规划**: 根据业务增长预测资源需求
3. **备份策略**: 建立完整的备份和恢复机制
4. **灾难恢复**: 制定灾难恢复预案
5. **安全加固**: 定期进行安全评估和加固

---

**文档版本**: v1.0.0
**最后更新**: 2025-11-27 16:30:00
**维护者**: Security Team
**联系方式**: security@example.com