#!/bin/bash

# TLS Key Agent 构建脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查依赖
check_dependencies() {
    log_info "检查构建依赖..."

    if ! command -v cargo &> /dev/null; then
        log_error "Cargo 未找到，请安装 Rust 工具链"
        exit 1
    fi

    if ! command -v rustc &> /dev/null; then
        log_error "Rust 编译器未找到"
        exit 1
    fi

    log_info "依赖检查完成"
}

# 清理构建目录
clean_build() {
    log_info "清理构建目录..."
    cargo clean
    log_info "构建目录清理完成"
}

# 构建发布版本
build_release() {
    log_info "开始构建发布版本..."

    # 构建二进制文件
    cargo build --release

    # 构建共享库
    cargo build --release --lib

    log_info "发布版本构建完成"

    # 显示构建产物
    log_info "构建产物："
    echo "  二进制文件: target/release/tls_key_agent"
    echo "  共享库: target/release/libtls_key_agent.so"
    echo "  静态库: target/release/libtls_key_agent.a"
}

# 构建调试版本
build_debug() {
    log_info "开始构建调试版本..."

    # 构建二进制文件
    cargo build

    # 构建共享库
    cargo build --lib

    log_info "调试版本构建完成"

    # 显示构建产物
    log_info "构建产物："
    echo "  二进制文件: target/debug/tls_key_agent"
    echo "  共享库: target/debug/libtls_key_agent.so"
    echo "  静态库: target/debug/libtls_key_agent.a"
}

# 运行测试
run_tests() {
    log_info "运行测试套件..."
    cargo test
    log_info "测试完成"
}

# 运行代码检查
run_checks() {
    log_info "运行代码检查..."

    # 检查代码格式
    cargo fmt -- --check

    # 运行 Clippy
    cargo clippy -- -D warnings

    log_info "代码检查完成"
}

# 安装到系统
install_system() {
    log_info "安装 TLS Key Agent 到系统..."

    # 检查权限
    if [[ $EUID -ne 0 ]]; then
        log_error "安装到系统需要 root 权限"
        exit 1
    fi

    # 创建目录
    mkdir -p /usr/local/bin
    mkdir -p /usr/local/lib
    mkdir -p /etc/tls_key_agent

    # 复制文件
    cp target/release/tls_key_agent /usr/local/bin/
    cp target/release/libtls_key_agent.so /usr/local/lib/
    cp config.toml /etc/tls_key_agent/config.toml.example

    # 设置权限
    chmod +x /usr/local/bin/tls_key_agent
    chmod 644 /usr/local/lib/libtls_key_agent.so

    log_info "安装完成"
    log_info "配置文件示例: /etc/tls_key_agent/config.toml.example"
    log_info "可执行文件: /usr/local/bin/tls_key_agent"
    log_info "共享库: /usr/local/lib/libtls_key_agent.so"
}

# 创建发布包
create_package() {
    log_info "创建发布包..."

    VERSION=$(cargo metadata --no-deps --format-version 1 | grep -o '"version":"[^"]*"' | head -1 | cut -d'"' -f4)
    PACKAGE_NAME="tls_key_agent-${VERSION}"

    # 创建临时目录
    mkdir -p "dist/${PACKAGE_NAME}"

    # 复制文件
    cp target/release/tls_key_agent "dist/${PACKAGE_NAME}/"
    cp target/release/libtls_key_agent.so "dist/${PACKAGE_NAME}/"
    cp config.toml "dist/${PACKAGE_NAME}/"
    cp README.md "dist/${PACKAGE_NAME}/"
    cp build.sh "dist/${PACKAGE_NAME}/"

    # 创建启动脚本
    cat > "dist/${PACKAGE_NAME}/start.sh" << 'EOF'
#!/bin/bash
# TLS Key Agent 启动脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.toml"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "配置文件不存在: $CONFIG_FILE"
    echo "请复制 config.toml.example 为 config.toml 并修改配置"
    exit 1
fi

echo "启动 TLS Key Agent..."
"$SCRIPT_DIR/tls_key_agent" --config "$CONFIG_FILE"
EOF

    chmod +x "dist/${PACKAGE_NAME}/start.sh"

    # 创建压缩包
    cd dist
    tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
    cd ..

    log_info "发布包创建完成: dist/${PACKAGE_NAME}.tar.gz"
}

# 显示帮助信息
show_help() {
    echo "TLS Key Agent 构建脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  clean       清理构建目录"
    echo "  debug       构建调试版本"
    echo "  release     构建发布版本 (默认)"
    echo "  test        运行测试套件"
    echo "  check       运行代码检查"
    echo "  install     安装到系统 (需要 root 权限)"
    echo "  package     创建发布包"
    echo "  help        显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 release"
    echo "  $0 debug"
    echo "  $0 test && $0 release"
}

# 主函数
main() {
    local command=${1:-release}

    log_info "TLS Key Agent 构建脚本启动"

    check_dependencies

    case $command in
        "clean")
            clean_build
            ;;
        "debug")
            build_debug
            ;;
        "release")
            build_release
            ;;
        "test")
            run_tests
            ;;
        "check")
            run_checks
            ;;
        "install")
            build_release
            install_system
            ;;
        "package")
            build_release
            create_package
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "未知命令: $command"
            show_help
            exit 1
            ;;
    esac

    log_info "构建脚本执行完成"
}

# 执行主函数
main "$@"