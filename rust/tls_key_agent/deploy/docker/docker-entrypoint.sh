#!/bin/bash
# TLS Key Agent Docker入口点脚本

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

# 处理信号
cleanup() {
    print_info "收到停止信号，正在关闭TLS Key Agent..."
    if [ -n "$AGENT_PID" ]; then
        kill $AGENT_PID 2>/dev/null || true
        wait $AGENT_PID 2>/dev/null || true
    fi
    print_success "TLS Key Agent已停止"
    exit 0
}

# 设置信号处理
trap cleanup SIGTERM SIGINT

# 检查配置文件
CONFIG_FILE=${CONFIG_FILE:-"/opt/tls_key_agent/config/config.toml"}
if [ ! -f "$CONFIG_FILE" ]; then
    print_error "配置文件不存在: $CONFIG_FILE"
    exit 1
fi

# 创建日志目录
mkdir -p /opt/tls_key_agent/logs

# 设置权限
chown -R tls-key-agent:tls-key-agent /opt/tls_key_agent/logs 2>/dev/null || true

print_info "启动TLS Key Agent..."
print_info "配置文件: $CONFIG_FILE"
print_info "运行用户: $(whoami)"
print_info "工作目录: $(pwd)"

# 启动应用
exec "$@" &
AGENT_PID=$!

# 等待进程
wait $AGENT_PID