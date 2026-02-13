#!/bin/bash
# TLS Key Agent 安装脚本

set -e

INSTALL_PREFIX=${INSTALL_PREFIX:-"/opt/tls_key_agent"}
SERVICE_USER=${SERVICE_USER:-"tls-key-agent"}
CREATE_SERVICE=${CREATE_SERVICE:-true}

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
    echo "TLS Key Agent 安装脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --prefix=PATH       安装前缀 (默认: /opt/tls_key_agent)"
    echo "  --user=USER         运行用户 (默认: tls-key-agent)"
    echo "  --no-service        不创建systemd服务"
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
        --no-service)
            CREATE_SERVICE=false
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

print_info "开始安装 TLS Key Agent..."
print_info "安装路径: $INSTALL_PREFIX"
print_info "运行用户: $SERVICE_USER"
print_info "创建服务: $CREATE_SERVICE"

# 创建用户
if ! id "$SERVICE_USER" &>/dev/null; then
    print_info "创建服务用户: $SERVICE_USER"
    useradd -r -s /bin/false -d "$INSTALL_PREFIX" "$SERVICE_USER"
fi

# 创建安装目录
mkdir -p "$INSTALL_PREFIX"/{bin,config,logs,scripts,docs}
cd "$(dirname "$0")"

# 复制文件
print_info "复制程序文件..."
cp -r bin/* "$INSTALL_PREFIX/bin/"
cp -r config/* "$INSTALL_PREFIX/config/"
cp -r scripts/* "$INSTALL_PREFIX/scripts/"
cp -r docs/* "$INSTALL_PREFIX/docs/" 2>/dev/null || true

# 设置权限
print_info "设置文件权限..."
chmod +x "$INSTALL_PREFIX/bin"/*
chmod +x "$INSTALL_PREFIX/scripts"/*
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_PREFIX"

# 创建systemd服务
if [ "$CREATE_SERVICE" = true ]; then
    print_info "创建systemd服务..."

    cat > /etc/systemd/system/tls-key-agent.service << EOS
[Unit]
Description=TLS Key Agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$INSTALL_PREFIX/bin/tls_key_agent --config $INSTALL_PREFIX/config/config.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tls-key-agent

# 安全设置
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$INSTALL_PREFIX/logs
CapabilityBoundingSet=CAP_SYS_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
EOS

    systemctl daemon-reload
    systemctl enable tls-key-agent
    print_success "systemd服务已创建"
fi

# 创建配置文件链接
if [ ! -f "$INSTALL_PREFIX/config/production.toml" ]; then
    cp "$INSTALL_PREFIX/config/config.toml" "$INSTALL_PREFIX/config/production.toml"
    print_info "已创建生产配置文件模板: $INSTALL_PREFIX/config/production.toml"
fi

print_success "TLS Key Agent 安装完成！"

if [ "$CREATE_SERVICE" = true ]; then
    echo ""
    print_info "启动服务:"
    echo "  systemctl start tls-key-agent"
    echo ""
    print_info "查看状态:"
    echo "  systemctl status tls-key-agent"
    echo ""
    print_info "查看日志:"
    echo "  journalctl -u tls-key-agent -f"
fi

echo ""
print_info "配置文件位置: $INSTALL_PREFIX/config/"
print_info "可执行文件: $INSTALL_PREFIX/bin/"
