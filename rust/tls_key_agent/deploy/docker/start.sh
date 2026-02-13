#!/bin/bash
# TLS Key Agent Docker启动脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

# 默认配置
CONFIG_FILE=${CONFIG_FILE:-"/opt/tls_key_agent/config/config.toml"}
LOG_LEVEL=${LOG_LEVEL:-"info"}

# 显示启动信息
print_info "TLS Key Agent Docker 启动脚本"
print_info "配置文件: $CONFIG_FILE"
print_info "日志级别: $LOG_LEVEL"
print_info "工作目录: $(pwd)"

# 检查eBPF支持
if ! lsmod | grep -q "bpf"; then
    print_warning "内核未加载BPF模块，eBPF功能可能不可用"
fi

# 检查权限
if [ "$(id -u)" != "0" ]; then
    print_warning "非root用户运行，某些功能可能受限"
    print_info "建议使用 --privileged 运行Docker容器"
fi

# 设置环境变量
export RUST_LOG=$LOG_LEVEL

# 创建必要的目录
mkdir -p /opt/tls_key_agent/{logs,run}

# 启动应用
print_info "启动TLS Key Agent..."
exec /opt/tls_key_agent/bin/tls_key_agent --config "$CONFIG_FILE"