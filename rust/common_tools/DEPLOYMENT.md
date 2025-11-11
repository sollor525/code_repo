# 开发者工具箱部署指南

本文档详细介绍了如何将开发者工具箱部署到另一台设备。

## 📋 目录

- [部署方案概览](#部署方案概览)
- [方案一：源码部署](#方案一源码部署)
- [方案二：二进制发布包部署](#方案二二进制发布包部署)
- [方案三：Docker容器部署](#方案三docker容器部署)
- [配置说明](#配置说明)
- [故障排除](#故障排除)
- [性能优化](#性能优化)

## 🚀 部署方案概览

| 方案 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| 源码部署 | 灵活、可定制 | 需要Rust环境 | 开发环境、定制需求 |
| 二进制包 | 部署简单、性能好 | 平台相关 | 生产环境、快速部署 |
| Docker | 跨平台、隔离性好 | 需要Docker环境 | 容器化环境、微服务架构 |

## 方案一：源码部署

### 系统要求

- Linux (Ubuntu 18.04+, CentOS 7+, Debian 9+)
- Rust 1.70+
- Git

### 部署步骤

1. **克隆代码**
```bash
git clone <repository-url>
cd common_tools
```

2. **运行自动部署脚本**
```bash
chmod +x deploy.sh
./deploy.sh
```

3. **手动部署（可选）**
```bash
# 安装Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 安装依赖 (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential pkg-config libssl-dev

# 安装依赖 (CentOS/RHEL)
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel pkg-config

# 构建项目
cargo build --release

# 创建systemd服务
sudo cp common-tools.service /etc/systemd/system/
sudo systemctl enable common-tools
sudo systemctl start common-tools
```

### 验证部署

访问：`http://<服务器IP>:8080`

## 方案二：二进制发布包部署

### 快速部署

1. **下载发布包**
```bash
# 选择适合您系统的包
wget https://releases.example.com/common-tools-v1.0.0-linux-x64-deploy.tar.gz
```

2. **解压部署**
```bash
tar -xzf common-tools-v1.0.0-linux-x64-deploy.tar.gz
cd common-tools-v1.0.0-deploy
```

3. **启动服务**
```bash
# 直接启动
./start.sh

# 或安装为系统服务
sudo cp common-tools.service /etc/systemd/system/
sudo systemctl enable common-tools
sudo systemctl start common-tools
```

### 手动构建发布包

```bash
# 在开发机器上执行
./build_release.sh
```

生成的文件：
- `release/common-tools-1.0.0-linux-x64.tar.gz` - 仅二进制文件
- `release/common-tools-1.0.0-deploy.tar.gz` - 完整部署包

## 方案三：Docker容器部署

### 前置要求

- Docker 20.03+
- Docker Compose 2.0+

### 快速启动

1. **克隆代码**
```bash
git clone <repository-url>
cd common_tools
```

2. **启动服务**
```bash
# 使用脚本
./docker-deploy.sh start

# 或使用docker-compose
docker-compose up -d
```

### Docker部署脚本

```bash
# 构建镜像
./docker-deploy.sh build

# 启动服务
./docker-deploy.sh start

# 查看状态
./docker-deploy.sh status

# 查看日志
./docker-deploy.sh logs

# 更新服务
./docker-deploy.sh update

# 停止服务
./docker-deploy.sh stop

# 清理资源
./docker-deploy.sh cleanup
```

### 生产环境配置

创建 `docker-compose.prod.yml`：

```yaml
version: '3.8'

services:
  common-tools:
    build: .
    container_name: common-tools
    ports:
      - "80:8080"
    environment:
      - RUST_LOG=warn
      - LISTEN_ADDRESS=0.0.0.0:8080
    restart: always
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    volumes:
      - ./logs:/app/logs
      - /etc/localtime:/etc/localtime:ro
    networks:
      - common-tools-network
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

networks:
  common-tools-network:
    driver: bridge

volumes:
  logs:
    driver: local
```

## ⚙️ 配置说明

### 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `RUST_LOG` | `info` | 日志级别 (debug/info/warn/error) |
| `LISTEN_ADDRESS` | `0.0.0.0:8080` | 监听地址和端口 |
| `STATIC_DIR` | `./static` | 静态文件目录 |

### 端口配置

- **HTTP端口**: 8080
- **健康检查**: `/health`

### 防火墙配置

```bash
# Ubuntu/Debian
sudo ufw allow 8080/tcp

# CentOS/RHEL
sudo firewall-cmd --add-port=8080/tcp --permanent
sudo firewall-cmd --reload
```

## 🔧 故障排除

### 常见问题

1. **端口被占用**
```bash
# 查看端口占用
sudo netstat -tlnp | grep 8080
# 或
sudo lsof -i :8080

# 停止占用进程
sudo kill -9 <PID>
```

2. **权限问题**
```bash
# 设置文件权限
chmod +x common_tools
chown -R $USER:$USER /path/to/common_tools
```

3. **依赖缺失**
```bash
# Ubuntu/Debian
sudo apt install build-essential pkg-config libssl-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install openssl-devel pkg-config
```

4. **服务启动失败**
```bash
# 查看systemd日志
sudo journalctl -u common-tools -f

# 查看详细错误
sudo journalctl -u common-tools --no-pager -l
```

### 日志配置

```bash
# 启用调试日志
export RUST_LOG=debug

# 查看应用日志
./common_tools

# 或使用systemd
sudo journalctl -u common-tools -f
```

## 📈 性能优化

### 系统优化

1. **文件描述符限制**
```bash
# 临时增加
ulimit -n 65536

# 永久设置
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf
```

2. **内核参数优化**
```bash
# 编辑 /etc/sysctl.conf
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf

# 应用配置
sudo sysctl -p
```

### 应用优化

1. **并发配置**
```bash
# 设置工作线程数
export TOKIO_WORKER_THREADS=4

# 启用Tokio控制台
export TOKIO_CONSOLE_ENABLED=true
```

2. **缓存配置**
```bash
# 启用文件缓存
export FILE_CACHE_ENABLED=true
export FILE_CACHE_SIZE=1000
```

## 🔒 安全配置

### SSL/TLS配置

```bash
# 使用反向代理 (Nginx)
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 访问控制

```bash
# IP白名单 (Nginx)
location / {
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;
    proxy_pass http://localhost:8080;
}
```

## 📞 技术支持

如遇到部署问题，请：

1. 检查系统日志
2. 确认环境配置
3. 验证网络连接
4. 查看GitHub Issues

## 🔄 更新升级

### 源码部署更新
```bash
git pull origin master
cargo build --release
sudo systemctl restart common-tools
```

### Docker更新
```bash
./docker-deploy.sh update
```

### 二进制包更新
```bash
# 停止服务
sudo systemctl stop common-tools

# 备份当前版本
cp common_tools common_tools.backup

# 替换二进制文件
cp new_common_tools common_tools

# 启动服务
sudo systemctl start common_tools
```