# TLS Key Agent 部署文档

## 概述

本文档详细介绍了TLS Key Agent在不同环境下的部署方法，包括单机部署、集群部署、容器化部署和云原生部署方案。TLS Key Agent采用**主动式Hook架构**，提供了灵活的部署选项来适应不同的生产环境需求。

## 🚀 主动式Hook部署特性

### 核心优势
- **无侵入部署**: 通过LD_PRELOAD方式，无需修改目标应用
- **独立Hook库**: `libtls_agent_hook.so`可独立部署和使用
- **高性能**: 直接Hook SSL函数，性能开销最小
- **灵活配置**: 支持环境变量和配置文件多种配置方式

## 目录

1. [部署架构](#部署架构)
2. [环境准备](#环境准备)
3. [单机部署](#单机部署)
4. [集群部署](#集群部署)
5. [容器化部署](#容器化部署)
6. [云原生部署](#云原生部署)
7. [高可用配置](#高可用配置)
8. [安全配置](#安全配置)
9. [监控和日志](#监控和日志)
10. [运维管理](#运维管理)

## 部署架构

### 推荐架构

```
┌─────────────────────────────────────────────────────────────┐
│                        负载均衡层                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  HAProxy    │  │   Nginx     │  │  Envoy      │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      应用层                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Web App   │  │    API      │  │ Background  │         │
│  │  Services   │  │  Services   │  │   Jobs      │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │ LD_PRELOAD
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  TLS Key Agent                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Agent 1   │  │   Agent 2   │  │   Agent N   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    收集层                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Kafka     │  │    Redis    │  │  Elastic    │         │
│  │   Cluster   │  │   Cluster   │  │  Search     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   分析层                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │    Spark    │  │   Flink     │  │  Grafana    │         │
│  │ Analytics   │  │ Streaming   │  │ Dashboard   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### 网络架构

```
Internet
    │
    ▼
┌─────────────┐
│   Firewall  │
└─────────────┘
    │
    ▼
┌─────────────┐
│ DMZ Network │  ← TLS Key Agent部署区
└─────────────┘
    │
    ▼
┌─────────────┐
│Internal Net │  ← 应用服务器
└─────────────┘
```

## 环境准备

### 系统要求

#### 最低配置
- **CPU**: 2核心
- **内存**: 4GB RAM
- **存储**: 20GB可用空间
- **网络**: 1Gbps网卡

#### 推荐配置
- **CPU**: 4核心以上
- **内存**: 8GB RAM以上
- **存储**: 100GB SSD
- **网络**: 10Gbps网卡

#### 软件依赖

```bash
# 基础依赖
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libcurl4-openssl-dev \
    systemd \
    curl \
    wget \
    git

# Rust工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 网络工具
sudo apt install -y \
    netcat-openbsd \
    telnet \
    nmap \
    iproute2
```

### 网络配置

```bash
# 检查网络接口
ip addr show

# 配置防火墙（以ufw为例）
sudo ufw enable
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 8080/tcp  # API端口
sudo ufw allow 9999/tcp  # TCP传输端口
sudo ufw allow 9999/udp  # UDP传输端口

# 配置内核参数
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 65536 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

## 单机部署

### 1. 安装部署

```bash
#!/bin/bash
# deploy_single.sh - 单机部署脚本

set -e

# 配置变量
INSTALL_DIR="/opt/tls_key_agent"
CONFIG_DIR="/etc/tls_key_agent"
LOG_DIR="/var/log/tls_key_agent"
USER="tls_agent"

echo "开始TLS Key Agent单机部署..."

# 创建用户
sudo useradd -r -s /bin/false -d $INSTALL_DIR $USER || true

# 创建目录
sudo mkdir -p $INSTALL_DIR $CONFIG_DIR $LOG_DIR

# 编译项目
cargo build --release

# 安装文件
sudo cp target/release/tls_key_agent $INSTALL_DIR/
sudo cp target/release/libopenssl_hook.so $INSTALL_DIR/
sudo cp target/release/verify_keys $INSTALL_DIR/
sudo cp config.toml $CONFIG_DIR/

# 设置权限
sudo chown -R $USER:$USER $INSTALL_DIR $CONFIG_DIR $LOG_DIR
sudo chmod 755 $INSTALL_DIR/tls_key_agent
sudo chmod 644 $INSTALL_DIR/libopenssl_hook.so
sudo chmod 644 $CONFIG_DIR/config.toml

# 创建systemd服务
sudo tee /etc/systemd/system/tls-key-agent.service > /dev/null <<EOF
[Unit]
Description=TLS Key Agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
Group=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/tls_key_agent --config $CONFIG_DIR/config.toml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
LimitNOFILE=65536

# 安全设置
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable tls-key-agent
sudo systemctl start tls-key-agent

echo "TLS Key Agent部署完成！"
echo "状态检查: sudo systemctl status tls-key-agent"
echo "日志查看: sudo journalctl -u tls-key-agent -f"
```

### 2. 配置优化

```toml
# 生产环境配置 - production.toml
[agent]
name = "tls_key_agent_prod"
log_level = "warn"  # 减少日志输出
buffer_pool_size = 5000
buffer_size = 16384
worker_threads = 4

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
batch_size = 50
batch_timeout = 100

[transport]
enabled_transports = ["Tcp", "File"]

[transport.tcp]
enabled = true
server_host = "192.168.1.100"
server_port = 9999
reconnect_interval = 5
max_reconnect_attempts = 10
timeout = 30
keepalive = true

[transport.file]
enabled = true
directory = "/var/log/tls_agent"
filename_pattern = "tls_keys_{timestamp}.log"
max_file_size = "1GB"
max_files = 30
compression = true

[[filters]]
name = "production_https"
enabled = true
priority = 100
five_tuple = { dst_port = 443 }
```

### 3. 监控配置

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'tls-key-agent'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
    scrape_interval: 5s
```

```bash
# 启动Prometheus
docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus

# 启动Grafana
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e "GF_SECURITY_ADMIN_PASSWORD=admin" \
  grafana/grafana
```

## 集群部署

### 1. 多节点部署架构

```
┌─────────────────────────────────────────────────────────────┐
│                      负载均衡器                             │
│                  (HAProxy/Keepalived)                       │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Node 1    │    │   Node 2    │    │   Node 3    │
│ TLS Agent   │    │ TLS Agent   │    │ TLS Agent   │
│ + Monitor   │    │ + Monitor   │    │ + Monitor   │
└─────────────┘    └─────────────┘    └─────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    密钥收集集群                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Kafka     │  │    Redis    │  │  Elastic    │         │
│  │  Cluster    │  │  Cluster    │  │  Search     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### 2. 集群部署脚本

```bash
#!/bin/bash
# deploy_cluster.sh - 集群部署脚本

set -e

# 集群配置
NODES=(
    "192.168.1.10:node1"
    "192.168.1.11:node2"
    "192.168.1.12:node3"
)
INSTALL_DIR="/opt/tls_key_agent"
CONFIG_DIR="/etc/tls_key_agent"
USER="tls_agent"

echo "开始TLS Key Agent集群部署..."

# 1. 在所有节点上部署基础环境
for node in "${NODES[@]}"; do
    IFS=':' read -r ip hostname <<< "$node"
    echo "部署节点: $hostname ($ip)"

    # SSH到远程节点执行部署
    ssh root@$ip <<EOF
        # 创建用户
        useradd -r -s /bin/false $USER || true

        # 创建目录
        mkdir -p $INSTALL_DIR $CONFIG_DIR /var/log/tls_agent

        # 同步文件
        rsync -avz --delete deploy@$HOSTNAME:/opt/tls_key_agent/ $INSTALL_DIR/

        # 设置权限
        chown -R $USER:$USER $INSTALL_DIR $CONFIG_DIR /var/log/tls_agent

        # 创建节点特定配置
        cat > $CONFIG_DIR/config.toml <<EOCONF
[agent]
name = "tls_key_agent_$hostname"
log_level = "info"
node_id = "$hostname"

[transport.tcp]
server_host = "192.168.1.100"
server_port = 9999

[[filters]]
name = "$hostname_https"
enabled = true
priority = 100
process_name = "nginx"
EOCONF
EOF
done

# 2. 部署负载均衡器
cat > haproxy.cfg <<EOF
global
    daemon
    maxconn 4096

defaults
    mode tcp
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend tls_agent_frontend
    bind *:9999
    default_backend tls_agent_backend

backend tls_agent_backend
    balance roundrobin
    option tcp-check
EOF

# 添加后端服务器
for node in "${NODES[@]}"; do
    IFS=':' read -r ip hostname <<< "$node"
    echo "    server $hostname $ip:9999 check" >> haproxy.cfg
done

# 3. 启动服务
for node in "${NODES[@]}"; do
    IFS=':' read -r ip hostname <<< "$node"
    ssh root@$ip "systemctl daemon-reload && systemctl enable tls-key-agent && systemctl start tls-key-agent"
done

echo "集群部署完成！"
echo "负载均衡器: http://$(hostname -I | awk '{print $1}'):9999"
```

### 3. 服务发现

```yaml
# consul-config.yaml
datacenter: dc1
data_dir: /opt/consul/data
log_level: INFO
server: true
bootstrap_expect: 3
retry_join:
  - "192.168.1.10"
  - "192.168.1.11"
  - "192.168.1.12"
```

```bash
# 启动Consul集群
docker run -d \
  --name consul \
  --net=host \
  -v $(pwd)/consul-config.yaml:/consul/config/config.yaml \
  consul:latest agent -config-dir=/consul/config

# 注册TLS Key Agent服务
curl -X PUT \
  -d '{
    "ID": "tls-key-agent-1",
    "Name": "tls-key-agent",
    "Address": "192.168.1.10",
    "Port": 8080,
    "Check": {
      "HTTP": "http://192.168.1.10:8080/health",
      "Interval": "10s"
    }
  }' \
  http://localhost:8500/v1/agent/service/register
```

## 容器化部署

### 1. Docker镜像构建

```dockerfile
# Dockerfile
FROM rust:1.75-slim as builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# 编译项目
RUN cargo build --release

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
RUN mkdir -p /app /etc/tls_key_agent /var/log/tls_agent

# 复制文件
COPY --from=builder /app/target/release/tls_key_agent /app/
COPY --from=builder /app/target/release/libopenssl_hook.so /app/
COPY --from=builder /app/target/release/verify_keys /app/
COPY config.toml /etc/tls_key_agent/

# 设置权限
RUN chown -R tls_agent:tls_agent /app /etc/tls_key_agent /var/log/tls_agent

# 切换用户
USER tls_agent

WORKDIR /app

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

CMD ["./tls_key_agent", "--config", "/etc/tls_key_agent/config.toml"]
```

```bash
# 构建镜像
docker build -t tls-key-agent:latest .

# 推送镜像
docker tag tls-key-agent:latest registry.example.com/tls-key-agent:latest
docker push registry.example.com/tls-key-agent:latest
```

### 2. Docker Compose部署

```yaml
# docker-compose.yml
version: '3.8'

services:
  tls-key-agent:
    image: tls-key-agent:latest
    container_name: tls-key-agent
    restart: unless-stopped
    environment:
      - RUST_LOG=info
      - TZ=Asia/Shanghai
    volumes:
      - ./config:/etc/tls_key_agent:ro
      - ./logs:/var/log/tls_agent
      - ./lib:/app/hooks
    ports:
      - "8080:8080"
    networks:
      - tls_agent_network
    depends_on:
      - kafka
      - redis

  kafka:
    image: confluentinc/cp-kafka:latest
    container_name: kafka
    environment:
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    ports:
      - "9092:9092"
    networks:
      - tls_agent_network

  redis:
    image: redis:alpine
    container_name: redis
    ports:
      - "6379:6379"
    networks:
      - tls_agent_network

  zookeeper:
    image: confluentinc/cp-zookeeper:latest
    container_name: zookeeper
    environment:
      ZOOKEEPER_CLIENT_PORT: 2181
      ZOOKEEPER_TICK_TIME: 2000
    networks:
      - tls_agent_network

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    networks:
      - tls_agent_network

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    networks:
      - tls_agent_network

networks:
  tls_agent_network:
    driver: bridge
```

```bash
# 启动服务
docker-compose up -d

# 查看状态
docker-compose ps

# 查看日志
docker-compose logs -f tls-key-agent
```

### 3. Kubernetes部署

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tls-key-agent
---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tls-key-agent-config
  namespace: tls-key-agent
data:
  config.toml: |
    [agent]
    name = "tls_key_agent_k8s"
    log_level = "info"

    [transport.tcp]
    enabled = true
    server_host = "kafka-service"
    server_port = 9092
---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tls-key-agent
  namespace: tls-key-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tls-key-agent
  template:
    metadata:
      labels:
        app: tls-key-agent
    spec:
      containers:
      - name: tls-key-agent
        image: tls-key-agent:latest
        imagePullPolicy: Always
        env:
        - name: RUST_LOG
          value: "info"
        ports:
        - containerPort: 8080
          name: http
        volumeMounts:
        - name: config
          mountPath: /etc/tls_key_agent
        - name: logs
          mountPath: /var/log/tls_agent
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: tls-key-agent-config
      - name: logs
        emptyDir: {}
---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: tls-key-agent-service
  namespace: tls-key-agent
spec:
  selector:
    app: tls-key-agent
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  type: ClusterIP
---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-key-agent-ingress
  namespace: tls-key-agent
spec:
  rules:
  - host: tls-key-agent.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: tls-key-agent-service
            port:
              number: 8080
```

```bash
# 部署到Kubernetes
kubectl apply -f k8s/

# 查看部署状态
kubectl get pods -n tls-key-agent

# 查看服务
kubectl get svc -n tls-key-agent

# 查看日志
kubectl logs -f deployment/tls-key-agent -n tls-key-agent
```

## 云原生部署

### 1. Helm Chart

```yaml
# Chart.yaml
apiVersion: v2
name: tls-key-agent
description: TLS Key Agent Helm Chart
type: application
version: 0.1.0
appVersion: "0.1.0"

# values.yaml
replicaCount: 3

image:
  repository: tls-key-agent
  pullPolicy: IfNotPresent
  tag: "latest"

service:
  type: ClusterIP
  port: 8080

ingress:
  enabled: true
  className: nginx
  annotations: {}
  hosts:
    - host: tls-key-agent.example.com
      paths:
        - path: /
          pathType: Prefix
  tls: []

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 250m
    memory: 256Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

config:
  logLevel: "info"
  tcpServerHost: "kafka-service"
  tcpServerPort: 9092
```

```bash
# 安装Helm Chart
helm install tls-key-agent ./tls-key-agent-chart

# 升级
helm upgrade tls-key-agent ./tls-key-agent-chart

# 卸载
helm uninstall tls-key-agent
```

### 2. AWS EKS部署

```yaml
# eks-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tls-key-agent
  namespace: tls-key-agent
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tls-key-agent
  template:
    metadata:
      labels:
        app: tls-key-agent
    spec:
      serviceAccountName: tls-key-agent
      containers:
      - name: tls-key-agent
        image: tls-key-agent:latest
        env:
        - name: RUST_LOG
          value: "info"
        - name: AWS_REGION
          value: "us-west-2"
        - name: KAFKA_BOOTSTRAP_SERVERS
          valueFrom:
            configMapKeyRef:
              name: kafka-config
              key: bootstrap.servers
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        volumeMounts:
        - name: config
          mountPath: /etc/tls_key_agent
      volumes:
      - name: config
        configMap:
          name: tls-key-agent-config
```

```bash
# 部署到EKS
kubectl apply -f eks-deployment.yaml

# 配置IAM角色
aws iam create-role \
  --role-name tls-key-agent-role \
  --assume-role-policy-document file://trust-policy.json

aws iam attach-role-policy \
  --role-name tls-key-agent-role \
  --policy-arn arn:aws:iam::aws:policy/CloudWatchFullAccess
```

## 高可用配置

### 1. 主备部署

```bash
#!/bin/bash
# deploy_ha.sh - 高可用部署脚本

MASTER_NODE="192.168.1.10"
BACKUP_NODE="192.168.1.11"
VIP="192.168.1.100"

# 配置Keepalived
cat > keepalived.conf <<EOF
! Configuration File for keepalived
global_defs {
    router_id LVS_DEVEL
}

vrrp_script chk_tls_agent {
    script "/usr/local/bin/check_tls_agent.sh"
    interval 2
    weight -20
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        $VIP
    }
    track_script {
        chk_tls_agent
    }
}
EOF

# 健康检查脚本
cat > check_tls_agent.sh <<'EOF'
#!/bin/bash
systemctl is-active tls-key-agent >/dev/null 2>&1
EOF

chmod +x check_tls_agent.sh

# 在主节点部署
ssh root@$MASTER_NODE <<EOF
    apt-get install -y keepalived
    cp keepalived.conf /etc/keepalived/
    systemctl enable keepalived
    systemctl start keepalived
EOF

# 在备节点部署
sed 's/state MASTER/state BACKUP/' keepalived.conf | \
sed 's/priority 100/priority 90/' | \
ssh root@$BACKUP_NODE 'cat > /etc/keepalived/keepalived.conf'

ssh root@$BACKUP_NODE <<EOF
    apt-get install -y keepalived
    systemctl enable keepalived
    systemctl start keepalived
EOF

echo "高可用部署完成，虚拟IP: $VIP"
```

### 2. 数据同步

```bash
#!/bin/bash
# sync_data.sh - 数据同步脚本

MASTER_DIR="/var/log/tls_agent"
BACKUP_DIR="/backup/tls_agent"
SYNC_INTERVAL=60

while true; do
    rsync -avz --delete \
        -e "ssh -i /home/tls_agent/.ssh/sync_key" \
        $MASTER_DIR/ \
        tls_agent@$BACKUP_NODE:$BACKUP_DIR/

    sleep $SYNC_INTERVAL
done
```

## 安全配置

### 1. TLS加密传输

```toml
# secure-config.toml
[agent]
name = "tls_key_agent_secure"

[transport.tcp]
enabled = true
server_host = "secure-server.example.com"
server_port = 9999

[transport.tcp.tls]
enabled = true
cert_file = "/etc/tls_key_agent/client.crt"
key_file = "/etc/tls_key_agent/client.key"
ca_file = "/etc/tls_key_agent/ca.crt"
verify_hostname = true

[security]
encryption_enabled = true
encryption_key_file = "/etc/tls_key_agent/encryption.key"
```

```bash
# 生成证书
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes

openssl req -new -newkey rsa:2048 -keyout client.key -out client.csr -nodes

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

### 2. 访问控制

```bash
# 配置iptables规则
iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP

# 配置用户权限
usermod -L tls_agent  # 锁定用户
chmod 750 /etc/tls_key_agent
chmod 640 /etc/tls_key_agent/config.toml
```

## 监控和日志

### 1. Prometheus监控

```yaml
# prometheus-config.yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'tls-key-agent'
    kubernetes_sd_configs:
    - role: pod
    relabel_configs:
    - source_labels: [__meta_kubernetes_pod_label_app]
      action: keep
      regex: tls-key-agent
    - source_labels: [__meta_kubernetes_pod_ip]
      target_label: __address__
      replacement: ${1}:8080
```

### 2. 日志收集

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/tls_agent/*.log
  fields:
    service: tls-key-agent
  fields_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "tls-key-agent-%{+yyyy.MM.dd}"
```

## 运维管理

### 1. 自动化部署脚本

```bash
#!/bin/bash
# deploy.sh - 统一部署脚本

set -e

DEPLOY_TYPE=${1:-single}
ENVIRONMENT=${2:-production}

case $DEPLOY_TYPE in
    "single")
        ./scripts/deploy_single.sh $ENVIRONMENT
        ;;
    "cluster")
        ./scripts/deploy_cluster.sh $ENVIRONMENT
        ;;
    "docker")
        ./scripts/deploy_docker.sh $ENVIRONMENT
        ;;
    "k8s")
        ./scripts/deploy_k8s.sh $ENVIRONMENT
        ;;
    *)
        echo "Usage: $0 [single|cluster|docker|k8s] [development|staging|production]"
        exit 1
        ;;
esac

echo "部署完成！"
```

### 2. 备份和恢复

```bash
#!/bin/bash
# backup.sh - 备份脚本

BACKUP_DIR="/backup/tls_key_agent/$(date +%Y%m%d_%H%M%S)"
CONFIG_DIR="/etc/tls_key_agent"
LOG_DIR="/var/log/tls_agent"

mkdir -p $BACKUP_DIR

# 备份配置
tar -czf $BACKUP_DIR/config.tar.gz $CONFIG_DIR/

# 备份日志
tar -czf $BACKUP_DIR/logs.tar.gz $LOG_DIR/

# 备份数据库（如果使用）
mysqldump -u root -p tls_agent > $BACKUP_DIR/database.sql

# 清理旧备份
find /backup/tls_key_agent -type d -mtime +7 -exec rm -rf {} \;

echo "备份完成: $BACKUP_DIR"
```

### 3. 升级维护

```bash
#!/bin/bash
# upgrade.sh - 升级脚本

VERSION=${1:-latest}

echo "开始升级到版本: $VERSION"

# 备份当前版本
./scripts/backup.sh

# 下载新版本
wget https://releases.example.com/tls-key-agent-$VERSION.tar.gz

# 停止服务
systemctl stop tls-key-agent

# 替换二进制文件
cp tls-key-agent-$VERSION/tls_key_agent /opt/tls_key_agent/
cp tls-key-agent-$VERSION/libopenssl_hook.so /opt/tls_key_agent/

# 启动服务
systemctl start tls-key-agent

# 验证升级
sleep 10
./scripts/health_check.sh

echo "升级完成！"
```

---

*部署文档版本: v0.1.0*
*最后更新: 2023-11-04*