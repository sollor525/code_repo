#!/bin/bash
# TLS Key Agent 编译打包脚本
# 用于将项目编译并打包为可部署的压缩包

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_header() {
    echo -e "${PURPLE}🔧 $1${NC}"
}

# 项目信息
PROJECT_NAME="tls_key_agent"
VERSION=${VERSION:-"0.1.0"}
BUILD_TIME=$(date +"%Y%m%d_%H%M%S")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# 构建配置
RELEASE_BUILD=${RELEASE_BUILD:-true}
TARGET_DIR=${TARGET_DIR:-"target"}
PACKAGE_DIR=${PACKAGE_DIR:-"dist"}
INSTALL_PREFIX=${INSTALL_PREFIX:-"/opt/tls_key_agent"}

print_header "TLS Key Agent 编译打包工具"
echo "版本: $VERSION"
echo "构建时间: $BUILD_TIME"
echo "Git提交: $GIT_COMMIT"
echo "构建模式: $([ "$RELEASE_BUILD" = true ] && echo "Release" || echo "Debug")"
echo ""

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            RELEASE_BUILD=false
            shift
            ;;
        --version=*)
            VERSION="${1#*=}"
            shift
            ;;
        --target-dir=*)
            TARGET_DIR="${1#*=}"
            shift
            ;;
        --package-dir=*)
            PACKAGE_DIR="${1#*=}"
            shift
            ;;
        --prefix=*)
            INSTALL_PREFIX="${1#*=}"
            shift
            ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo ""
            echo "选项:"
            echo "  --debug              构建Debug版本 (默认Release)"
            echo "  --version=VERSION    指定版本号"
            echo "  --target-dir=DIR     指定构建目录"
            echo "  --package-dir=DIR    指定打包目录"
            echo "  --prefix=PREFIX      指定安装前缀"
            echo "  --help, -h           显示此帮助信息"
            exit 0
            ;;
        *)
            print_error "未知参数: $1"
            exit 1
            ;;
    esac
done

# 检查依赖
check_dependencies() {
    print_info "检查构建依赖..."

    # 检查Rust工具链
    if ! command -v cargo &> /dev/null; then
        print_error "Cargo 未安装，请先安装Rust工具链"
        exit 1
    fi

    # 检查其他工具
    local missing_tools=()

    for tool in tar gzip; do
        if ! command -v $tool &> /dev/null; then
            missing_tools+=($tool)
        fi
    done

    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_error "缺少工具: ${missing_tools[*]}"
        exit 1
    fi

    print_success "依赖检查通过"
}

# 清理旧的构建
clean_build() {
    print_info "清理旧的构建文件..."

    if [ -d "$PACKAGE_DIR" ]; then
        rm -rf "$PACKAGE_DIR"
        print_info "已清理打包目录: $PACKAGE_DIR"
    fi

    # 清理target目录
    cargo clean
    print_success "清理完成"
}

# 编译项目
build_project() {
    print_info "开始编译项目..."

    local build_mode=""
    if [ "$RELEASE_BUILD" = true ]; then
        build_mode="--release"
    else
        build_mode=""
    fi

    # 设置编译环境变量
    export RUSTFLAGS="-C target-cpu=native"

    # 编译
    cargo build $build_mode

    if [ "$RELEASE_BUILD" = true ]; then
        BINARY_PATH="$TARGET_DIR/release/tls_key_agent"
        VERIFY_PATH="$TARGET_DIR/release/verify_keys"
    else
        BINARY_PATH="$TARGET_DIR/debug/tls_key_agent"
        VERIFY_PATH="$TARGET_DIR/debug/verify_keys"
    fi

    if [ -f "$BINARY_PATH" ]; then
        print_success "编译成功: $BINARY_PATH"

        # 显示二进制信息
        print_info "二进制信息:"
        echo "  文件大小: $(du -h $BINARY_PATH | cut -f1)"
        echo "  架构: $(file $BINARY_PATH | grep -o 'x86-64\|aarch64\|arm')"
        echo "  动态依赖: $(ldd $BINARY_PATH 2>/dev/null | wc -l) 个"
    else
        print_error "编译失败，未找到二进制文件"
        exit 1
    fi
}

# 创建打包目录结构
create_package_structure() {
    print_info "创建打包目录结构..." >&2

    # 创建临时打包目录
    local temp_package_dir="$PACKAGE_DIR/$PROJECT_NAME-$VERSION"
    mkdir -p "$temp_package_dir"

    # 创建目录结构
    mkdir -p "$temp_package_dir"/{bin,config,logs,scripts,docs}

    print_success "打包目录结构创建完成: $temp_package_dir" >&2

    # 只返回路径，不包含其他输出
    echo "$temp_package_dir"
}

# 复制文件到打包目录
copy_files() {
    local temp_package_dir=$1

    print_info "复制文件到打包目录..." >&2

    # 复制二进制文件
    cp "$BINARY_PATH" "$temp_package_dir/bin/"
    if [ -f "$VERIFY_PATH" ]; then
        cp "$VERIFY_PATH" "$temp_package_dir/bin/"
    fi

    # 复制配置文件
    cp config.toml "$temp_package_dir/config/"
    cp demo/demo_config.toml "$temp_package_dir/config/demo_config.toml"

    # 复制文档
    cp README.md "$temp_package_dir/docs/"
    cp -r docs/* "$temp_package_dir/docs/" 2>/dev/null || true

    # 复制演示文件
    cp -r demo/* "$temp_package_dir/" 2>/dev/null || true

    # 复制许可证文件
    cp LICENSE* "$temp_package_dir/" 2>/dev/null || true

    print_success "文件复制完成" >&2
}

# 创建部署脚本
create_deployment_scripts() {
    local temp_package_dir=$1

    print_info "创建部署脚本..." >&2

    # 创建安装脚本
    cat > "$temp_package_dir/scripts/install.sh" << 'EOF'
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

# 切换到脚本所在目录的上级目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)"
cd "$SCRIPT_DIR"

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
EOF

    # 创建卸载脚本
    cat > "$temp_package_dir/scripts/uninstall.sh" << 'EOF'
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
EOF

    # 设置脚本权限
    chmod +x "$temp_package_dir/scripts"/*.sh

    print_success "部署脚本创建完成" >&2
}

# 创建版本信息文件
create_version_info() {
    local temp_package_dir=$1

    print_info "创建版本信息文件..." >&2

    cat > "$temp_package_dir/VERSION" << EOF
Project: $PROJECT_NAME
Version: $VERSION
Build Time: $BUILD_TIME
Git Commit: $GIT_COMMIT
Build Mode: $([ "$RELEASE_BUILD" = true ] && echo "Release" || echo "Debug")
Target OS: $(uname -s)
Target Arch: $(uname -m)
Rust Version: $(rustc --version 2>/dev/null | cut -d' ' -f2 || echo "unknown")
EOF

    print_success "版本信息文件创建完成" >&2
}

# 创建压缩包
create_package() {
    local temp_package_dir=$1
    local package_name="$PROJECT_NAME-$VERSION-$BUILD_TIME"

    print_info "创建压缩包..." >&2

    # 进入打包目录
    cd "$PACKAGE_DIR"

    # 创建tar.gz包
    tar -czf "${package_name}.tar.gz" "$(basename $temp_package_dir)"

    # 计算文件大小和MD5
    local package_size=$(du -h "${package_name}.tar.gz" | cut -f1)
    local package_md5=$(md5sum "${package_name}.tar.gz" | cut -d' ' -f1)

    print_success "压缩包创建完成"
    print_info "包名: ${package_name}.tar.gz"
    print_info "大小: $package_size"
    print_info "MD5: $package_md5"

    # 创建安装说明文件
    cat > "${package_name}_INSTALL.txt" << EOF
TLS Key Agent 安装说明
======================

文件信息:
- 包名: ${package_name}.tar.gz
- 大小: $package_size
- MD5: $package_md5
- 版本: $VERSION

快速安装:
1. 解压: tar -xzf ${package_name}.tar.gz
2. 进入: cd ${PROJECT_NAME}-$VERSION
3. 安装: sudo ./scripts/install.sh

高级安装选项:
- 自定义安装路径: sudo ./scripts/install.sh --prefix=/custom/path
- 指定运行用户: sudo ./scripts/install.sh --user=myuser
- 不创建服务: sudo ./scripts/install.sh --no-service

卸载:
- 卸载程序: sudo $INSTALL_PREFIX/scripts/uninstall.sh

更多信息请查看 docs/ 目录下的文档。
EOF
}

# 创建系统服务包
create_service_package() {
    print_info "创建系统服务包..."

    local temp_package_dir=$1
    local package_name="$PROJECT_NAME-$VERSION-service"

    # 创建服务包目录
    mkdir -p "$PACKAGE_DIR/$package_name"

    # 创建systemd服务文件
    cat > "$PACKAGE_DIR/$package_name/tls-key-agent.service" << EOF
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
EOF

    print_success "系统服务包创建完成"
}

# 显示打包结果
show_package_result() {
    print_header "打包完成"

    echo "打包目录: $PACKAGE_DIR"
    echo ""

    # 显示生成的文件
    if [ -d "$PACKAGE_DIR" ]; then
        print_info "生成的文件:"
        ls -la "$PACKAGE_DIR" | grep -E '\.(tar\.gz|txt|service)$' || true
    fi

    echo ""
    print_info "下一步操作:"
    echo "1. 测试安装: tar -xzf $PACKAGE_DIR/*.tar.gz && cd ${PROJECT_NAME}-$VERSION && sudo ./scripts/install.sh"
    echo "2. 部署到服务器: 复制 $PACKAGE_DIR/*.tar.gz 到目标服务器"
    echo "3. 查看安装说明: $PACKAGE_DIR/*_INSTALL.txt"
}

# 主函数
main() {
    print_info "开始编译打包流程..."

    check_dependencies
    clean_build
    build_project

    local temp_package_dir=$(create_package_structure)
    copy_files "$temp_package_dir"
    create_deployment_scripts "$temp_package_dir"
    create_version_info "$temp_package_dir"
    create_package "$temp_package_dir"
    create_service_package "$temp_package_dir"

    # 清理临时目录
    rm -rf "$temp_package_dir"

    show_package_result
}

# 执行主函数
main "$@"