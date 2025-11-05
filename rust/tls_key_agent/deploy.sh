#!/bin/bash

# TLS Key Agent 自动化部署脚本
# 支持生产环境自动化部署

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 默认配置
DEFAULT_INSTALL_DIR="/opt/tls_key_agent"
DEFAULT_CONFIG_FILE="/etc/tls_key_agent/config.toml"
DEFAULT_SERVICE_USER="tls_agent"
DEFAULT_LOG_DIR="/var/log/tls_key_agent"
DEFAULT_RUN_DIR="/run/tls_key_agent"

# 显示帮助信息
show_help() {
    cat << EOF
TLS Key Agent 自动化部署脚本

用法: $0 [选项]

选项:
    -h, --help              显示此帮助信息
    -i, --install-dir DIR   安装目录 (默认: $DEFAULT_INSTALL_DIR)
    -c, --config FILE       配置文件路径 (默认: $DEFAULT_CONFIG_FILE)
    -u, --user USER         运行用户 (默认: $DEFAULT_SERVICE_USER)
    -l, --log-dir DIR       日志目录 (默认: $DEFAULT_LOG_DIR)
    -r, --run-dir DIR       运行目录 (默认: $DEFAULT_RUN_DIR)
    -m, --mode MODE         部署模式: debug|release|production (默认: production)
    -f, --force             强制覆盖已存在的文件
    --skip-deps             跳过依赖检查
    --skip-build            跳过编译步骤
    --uninstall             卸载TLS Key Agent

示例:
    $0                                    # 生产环境部署
    $0 -m debug -i ~/tls_key_agent       # 开发模式部署到用户目录
    $0 --uninstall                        # 卸载
EOF
}

# 检查是否以root权限运行
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_info "检测到root权限，继续部署..."
        return 0
    else
        log_warning "当前用户不是root，某些操作可能失败"
        if [[ "${INSTALL_DIR}" == "/opt"* ]] || [[ "${CONFIG_FILE}" == "/etc"* ]]; then
            log_error "系统目录安装需要root权限"
            exit 1
        fi
        return 0
    fi
}

# 检查系统环境
check_system() {
    log_info "检查系统环境..."

    # 检查操作系统
    if [[ ! -f /etc/os-release ]]; then
        log_error "无法检测操作系统"
        exit 1
    fi

    source /etc/os-release
    log_info "操作系统: $PRETTY_NAME"

    # 检查架构
    ARCH=$(uname -m)
    log_info "系统架构: $ARCH"

    # 检查内核版本
    KERNEL_VERSION=$(uname -r)
    log_info "内核版本: $KERNEL_VERSION"

    # 检查eBPF支持
    check_ebpf_support

    log_success "系统环境检查完成"
}

# 检查eBPF支持
check_ebpf_support() {
    log_info "检查eBPF支持..."

    # 检查内核版本
    local kernel_major=$(echo $KERNEL_VERSION | cut -d. -f1)
    local kernel_minor=$(echo $KERNEL_VERSION | cut -d. -f2)

    if [[ $kernel_major -lt 4 ]] || [[ $kernel_major -eq 4 && $kernel_minor -lt 14 ]]; then
        log_warning "内核版本过低 ($KERNEL_VERSION)，eBPF功能可能不可用"
        return 1
    fi

    # 检查eBPF文件系统
    if [[ ! -d /sys/fs/bpf ]]; then
        log_warning "eBPF文件系统未挂载，请运行: mount -t bpf bpf /sys/fs/bpf"
        return 1
    fi

    # 检查必要工具
    local missing_tools=()

    if ! command -v clang &> /dev/null; then
        missing_tools+=("clang")
    fi

    if ! command -v bpftool &> /dev/null; then
        missing_tools+=("bpftool")
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_warning "缺少eBPF工具: ${missing_tools[*]}"
        log_info "Ubuntu/Debian: apt install clang llvm linux-tools-common"
        log_info "CentOS/RHEL: yum install clang bpftool"
        return 1
    fi

    log_success "eBPF支持检查通过"
    return 0
}

# 检查依赖
check_dependencies() {
    log_info "检查系统依赖..."

    local missing_deps=()

    # 检查Rust
    if ! command -v cargo &> /dev/null; then
        missing_deps+=("rust/cargo")
    fi

    # 检查编译工具
    if ! command -v gcc &> /dev/null; then
        missing_deps+=("gcc")
    fi

    if ! command -v make &> /dev/null; then
        missing_deps+=("make")
    fi

    # 检查OpenSSL开发库
    if ! pkg-config --exists openssl 2>/dev/null; then
        missing_deps+=("libssl-dev")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少依赖: ${missing_deps[*]}"

        # 提供安装建议
        if command -v apt &> /dev/null; then
            log_info "Ubuntu/Debian系统安装命令:"
            log_info "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            log_info "  apt update && apt install -y build-essential libssl-dev pkg-config"
        elif command -v yum &> /dev/null; then
            log_info "CentOS/RHEL系统安装命令:"
            log_info "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            log_info "  yum groupinstall -y 'Development Tools'"
            log_info "  yum install -y openssl-devel pkgconfig"
        else
            log_info "请安装Rust和基础编译工具"
        fi

        exit 1
    fi

    log_success "依赖检查通过"
}

# 安装文件
install_files() {
    log_info "安装TLS Key Agent文件..."

    # 创建目录
    local dirs=("$INSTALL_DIR" "$DEFAULT_LOG_DIR" "$DEFAULT_RUN_DIR" "$(dirname "$CONFIG_FILE")")
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            if ! mkdir -p "$dir"; then
                log_error "无法创建目录: $dir"
                exit 1
            fi
            log_info "创建目录: $dir"
        fi
    done

    # 复制可执行文件
    local binary_name="tls_key_agent"
    local binary_source="target/$DEPLOY_MODE/$binary_name"
    local binary_dest="$INSTALL_DIR/$binary_name"

    if [[ ! -f "$binary_source" ]]; then
        if [[ "$SKIP_BUILD" == "true" ]]; then
            log_error "二进制文件不存在且跳过编译: $binary_source"
            exit 1
        fi
        log_info "二进制文件不存在，开始编译..."
        build_project
    fi

    if ! cp "$binary_source" "$binary_dest"; then
        log_error "无法复制二进制文件"
        exit 1
    fi

    chmod 755 "$binary_dest"
    log_success "安装二进制文件: $binary_dest"

    # 复制Hook库
    local hook_lib_source="target/$DEPLOY_MODE/libopenssl_hook.so"
    if [[ -f "$hook_lib_source" ]]; then
        local hook_lib_dest="$INSTALL_DIR/libopenssl_hook.so"
        if ! cp "$hook_lib_source" "$hook_lib_dest"; then
            log_error "无法复制Hook库"
            exit 1
        fi
        chmod 644 "$hook_lib_dest"
        log_success "安装Hook库: $hook_lib_dest"
    fi

    # 复制eBPF程序
    local ebpf_source="target/ebpf_monitor.o"
    if [[ -f "$ebpf_source" ]]; then
        local ebpf_dest="$INSTALL_DIR/ebpf_monitor.o"
        if ! cp "$ebpf_source" "$ebpf_dest"; then
            log_error "无法复制eBPF程序"
            exit 1
        fi
        chmod 644 "$ebpf_dest"
        log_success "安装eBPF程序: $ebpf_dest"
    fi

    # 创建配置文件
    create_config_file

    # 创建systemd服务文件
    create_service_file

    # 创建日志轮转配置
    create_logrotate_config

    log_success "文件安装完成"
}

# 创建配置文件
create_config_file() {
    if [[ -f "$CONFIG_FILE" && "$FORCE" != "true" ]]; then
        log_warning "配置文件已存在: $CONFIG_FILE (使用 --force 强制覆盖)"
        return 0
    fi

    log_info "创建配置文件: $CONFIG_FILE"

    cat > "$CONFIG_FILE" << 'EOF'
# TLS Key Agent 配置文件

[agent]
name = "tls_key_agent"
version = "0.1.0"
log_level = "info"
buffer_pool_size = 1000
buffer_size = 8192

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
capture_session_ticket = false
library_path = "/opt/tls_key_agent/libopenssl_hook.so"

[transport]
enabled_transports = ["Tcp", "File"]

[transport.tcp]
enabled = true
server_host = "127.0.0.1"
server_port = 9999
reconnect_interval = 5
max_retries = 10
timeout = 10

[transport.file]
enabled = true
output_path = "/var/log/tls_key_agent/tls_keys.log"
rotation = true
max_file_size = 104857600  # 100MB
max_files = 10

[injection]
enabled = true
method = "auto"  # "preload", "ebpf", "auto"
hook_library = "/opt/tls_key_agent/libopenssl_hook.so"
auto_inject = true
skip_critical_processes = true
injection_timeout = 30
max_injected_processes = 1000
process_discovery_interval = 5

# 过滤规则示例
[[filters]]
name = "http_https"
enabled = true

[filters.five_tuple]
dst_port = 80
protocol = "TCP"

[[filters]]
name = "https_traffic"
enabled = true

[filters.five_tuple]
dst_port = 443
protocol = "TCP"

[[filters]]
name = "web_servers"
enabled = true
process_name = "nginx|apache|httpd|lighttpd|caddy"
EOF

    chmod 644 "$CONFIG_FILE"
    log_success "配置文件创建完成"
}

# 创建systemd服务文件
create_service_file() {
    local service_file="/etc/systemd/system/tls_key_agent.service"

    if [[ -f "$service_file" && "$FORCE" != "true" ]]; then
        log_warning "systemd服务文件已存在: $service_file (使用 --force 强制覆盖)"
        return 0
    fi

    log_info "创建systemd服务文件: $service_file"

    cat > "$service_file" << EOF
[Unit]
Description=TLS Key Agent
After=network.target
Documentation=https://github.com/your-org/tls_key_agent

[Service]
Type=simple
User=$DEFAULT_SERVICE_USER
Group=$DEFAULT_SERVICE_USER
ExecStart=$INSTALL_DIR/tls_key_agent -c $CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tls_key_agent

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$DEFAULT_LOG_DIR $DEFAULT_RUN_DIR /sys/fs/bpf
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true

# 环境变量
Environment=RUST_LOG=info
Environment=LD_LIBRARY_PATH=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载systemd
    if command -v systemctl &> /dev/null; then
        systemctl daemon-reload
        log_success "systemd服务文件创建完成"
    else
        log_warning "systemd不可用，服务文件已创建但需要手动管理"
    fi
}

# 创建日志轮转配置
create_logrotate_config() {
    local logrotate_file="/etc/logrotate.d/tls_key_agent"

    if [[ -f "$logrotate_file" && "$FORCE" != "true" ]]; then
        log_warning "日志轮转配置已存在: $logrotate_file (使用 --force 强制覆盖)"
        return 0
    fi

    log_info "创建日志轮转配置: $logrotate_file"

    cat > "$logrotate_file" << EOF
$DEFAULT_LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $DEFAULT_SERVICE_USER $DEFAULT_SERVICE_USER
    postrotate
        systemctl reload tls_key_agent >/dev/null 2>&1 || true
    endscript
}
EOF

    log_success "日志轮转配置创建完成"
}

# 创建服务用户
create_service_user() {
    if id "$DEFAULT_SERVICE_USER" &>/dev/null; then
        log_info "服务用户已存在: $DEFAULT_SERVICE_USER"
        return 0
    fi

    if ! useradd -r -s /bin/false -d /nonexistent "$DEFAULT_SERVICE_USER"; then
        log_error "无法创建服务用户: $DEFAULT_SERVICE_USER"
        exit 1
    fi

    log_success "创建服务用户: $DEFAULT_SERVICE_USER"
}

# 设置权限
setup_permissions() {
    log_info "设置文件权限..."

    chown -R "$DEFAULT_SERVICE_USER:$DEFAULT_SERVICE_USER" "$DEFAULT_LOG_DIR"
    chown -R "$DEFAULT_SERVICE_USER:$DEFAULT_SERVICE_USER" "$DEFAULT_RUN_DIR"
    chmod 755 "$INSTALL_DIR"
    chown -R "$DEFAULT_SERVICE_USER:$DEFAULT_SERVICE_USER" "$INSTALL_DIR"

    # 设置eBPF文件系统权限
    if [[ -d /sys/fs/bpf ]]; then
        chmod 755 /sys/fs/bpf
        chown "$DEFAULT_SERVICE_USER:$DEFAULT_SERVICE_USER" /sys/fs/bpf 2>/dev/null || true
    fi

    log_success "权限设置完成"
}

# 编译项目
build_project() {
    log_info "编译TLS Key Agent ($DEPLOY_MODE模式)..."

    # 设置Rust环境变量
    export RUSTFLAGS="-C target-cpu=native"

    if [[ "$DEPLOY_MODE" == "debug" ]]; then
        if ! cargo build; then
            log_error "编译失败"
            exit 1
        fi
    else
        if ! cargo build --release; then
            log_error "编译失败"
            exit 1
        fi
    fi

    # 编译eBPF程序
    if [[ -f "src/ebpf_monitor_simple.c" ]]; then
        log_info "编译eBPF程序..."
        local clang_args=(
            "-O2"
            "-target" "bpf"
            "-c" "src/ebpf_monitor_simple.c"
            "-o" "target/ebpf_monitor.o"
            "-I/usr/include"
            "-I/usr/include/x86_64-linux-gnu"
            "-D__KERNEL__"
            "-Wno-unused-value"
            "-Wno-pointer-sign"
            "-Wno-compare-distinct-pointer-types"
        )

        if ! clang "${clang_args[@]}"; then
            log_warning "eBPF程序编译失败，eBPF功能将不可用"
        else
            log_success "eBPF程序编译完成"
        fi
    fi

    log_success "项目编译完成"
}

# 启用并启动服务
enable_service() {
    if ! command -v systemctl &> /dev/null; then
        log_warning "systemd不可用，请手动启动服务"
        return 0
    fi

    log_info "启用并启动TLS Key Agent服务..."

    if ! systemctl enable tls_key_agent; then
        log_error "无法启用服务"
        exit 1
    fi

    if ! systemctl start tls_key_agent; then
        log_error "无法启动服务"
        exit 1
    fi

    if systemctl is-active --quiet tls_key_agent; then
        log_success "TLS Key Agent服务已启动"
    else
        log_error "服务启动失败"
        systemctl status tls_key_agent
        exit 1
    fi
}

# 验证安装
verify_installation() {
    log_info "验证安装..."

    # 检查文件是否存在
    local required_files=(
        "$INSTALL_DIR/tls_key_agent"
        "$CONFIG_FILE"
    )

    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "必需文件不存在: $file"
            exit 1
        fi
    done

    # 检查服务状态
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet tls_key_agent; then
            log_success "服务运行正常"
        else
            log_warning "服务未运行"
        fi
    fi

    # 测试命令行工具
    if "$INSTALL_DIR/tls_key_agent" --help &>/dev/null; then
        log_success "命令行工具测试通过"
    else
        log_error "命令行工具测试失败"
        exit 1
    fi

    log_success "安装验证完成"
}

# 卸载TLS Key Agent
uninstall() {
    log_info "卸载TLS Key Agent..."

    # 停止并禁用服务
    if command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet tls_key_agent; then
            systemctl stop tls_key_agent || true
        fi
        if systemctl is-enabled --quiet tls_key_agent; then
            systemctl disable tls_key_agent || true
        fi
        rm -f /etc/systemd/system/tls_key_agent.service
        systemctl daemon-reload || true
    fi

    # 删除文件
    rm -rf "$INSTALL_DIR"
    rm -f "$CONFIG_FILE"
    rm -f /etc/logrotate.d/tls_key_agent

    # 删除用户（可选）
    read -p "是否删除服务用户 $DEFAULT_SERVICE_USER? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        userdel "$DEFAULT_SERVICE_USER" || true
        log_info "删除服务用户"
    fi

    log_success "TLS Key Agent卸载完成"
}

# 主函数
main() {
    local INSTALL_DIR="$DEFAULT_INSTALL_DIR"
    local CONFIG_FILE="$DEFAULT_CONFIG_FILE"
    local DEPLOY_MODE="production"
    local FORCE="false"
    local SKIP_DEPS="false"
    local SKIP_BUILD="false"

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -i|--install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -u|--user)
                DEFAULT_SERVICE_USER="$2"
                shift 2
                ;;
            -l|--log-dir)
                DEFAULT_LOG_DIR="$2"
                shift 2
                ;;
            -r|--run-dir)
                DEFAULT_RUN_DIR="$2"
                shift 2
                ;;
            -m|--mode)
                DEPLOY_MODE="$2"
                if [[ ! "$DEPLOY_MODE" =~ ^(debug|release|production)$ ]]; then
                    log_error "无效的部署模式: $DEPLOY_MODE"
                    exit 1
                fi
                # production模式等同于release
                if [[ "$DEPLOY_MODE" == "production" ]]; then
                    DEPLOY_MODE="release"
                fi
                shift 2
                ;;
            -f|--force)
                FORCE="true"
                shift
                ;;
            --skip-deps)
                SKIP_DEPS="true"
                shift
                ;;
            --skip-build)
                SKIP_BUILD="true"
                shift
                ;;
            --uninstall)
                uninstall
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # 检查是否在项目目录中
    if [[ ! -f "Cargo.toml" ]]; then
        log_error "请在TLS Key Agent项目根目录中运行此脚本"
        exit 1
    fi

    log_info "TLS Key Agent 自动化部署开始..."
    log_info "安装目录: $INSTALL_DIR"
    log_info "配置文件: $CONFIG_FILE"
    log_info "部署模式: $DEPLOY_MODE"
    log_info "服务用户: $DEFAULT_SERVICE_USER"

    # 检查root权限
    check_root

    # 检查系统环境
    check_system

    # 检查依赖
    if [[ "$SKIP_DEPS" != "true" ]]; then
        check_dependencies
    fi

    # 创建服务用户
    create_service_user

    # 编译项目
    if [[ "$SKIP_BUILD" != "true" ]]; then
        build_project
    fi

    # 安装文件
    install_files

    # 设置权限
    setup_permissions

    # 启用服务
    enable_service

    # 验证安装
    verify_installation

    log_success "TLS Key Agent部署完成!"
    log_info ""
    log_info "使用说明:"
    log_info "  查看服务状态: systemctl status tls_key_agent"
    log_info "  查看日志: journalctl -u tls_key_agent -f"
    log_info "  重启服务: systemctl restart tls_key_agent"
    log_info "  配置文件: $CONFIG_FILE"
    log_info "  日志目录: $DEFAULT_LOG_DIR"
    log_info ""
    log_info "更多信息请参考文档: https://github.com/your-org/tls_key_agent"
}

# 运行主函数
main "$@"