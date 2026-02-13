#!/bin/bash
# TLS Key Agent 卸载脚本

set -e

INSTALL_PREFIX=${INSTALL_PREFIX:-"/opt/tls_key_agent"}
SERVICE_USER=${SERVICE_USER:-"tls-key-agent"}
REMOVE_USER=${REMOVE_USER:-true}

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

show_help() {
    echo "TLS Key Agent 卸载脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --prefix=PATH       安装路径 (默认: /opt/tls_key_agent)"
    echo "  --user=USER         运行用户 (默认: tls-key-agent)"
    echo "  --keep-user         保留服务用户"
    echo "  --help, -h          显示此帮助信息"
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --prefix=*)
            INSTALL_PREFIX="${1#*=}"
            ;;
        --user=*)
            SERVICE_USER="${1#*=}"
            ;;
        --keep-user)
            REMOVE_USER=false
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            print_error "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

# 检查权限
if [[ $EUID -ne 0 ]]; then
    print_error "此脚本需要root权限运行"
    exit 1
fi

print_warning "即将卸载 TLS Key Agent"
print_info "安装路径: $INSTALL_PREFIX"
print_info "运行用户: $SERVICE_USER"

# 确认卸载
read -p "确认卸载? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "取消卸载"
    exit 0
fi

# 停止并删除服务
if systemctl list-unit-files | grep -q "tls-key-agent.service"; then
    print_info "停止systemd服务..."
    systemctl stop tls-key-agent 2>/dev/null || true
    systemctl disable tls-key-agent 2>/dev/null || true
    rm -f /etc/systemd/system/tls-key-agent.service
    systemctl daemon-reload
    print_success "systemd服务已删除"
fi

# 删除文件
if [ -d "$INSTALL_PREFIX" ]; then
    print_info "删除程序文件..."
    rm -rf "$INSTALL_PREFIX"
    print_success "程序文件已删除"
fi

# 删除用户
if [ "$REMOVE_USER" = true ] && id "$SERVICE_USER" &>/dev/null; then
    print_info "删除服务用户..."
    userdel "$SERVICE_USER" 2>/dev/null || true
    print_success "服务用户已删除"
fi

print_success "TLS Key Agent 卸载完成！"
