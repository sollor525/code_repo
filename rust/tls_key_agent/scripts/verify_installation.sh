#!/bin/bash

# TLS Key Agent 安装验证脚本

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

# 默认路径
INSTALL_DIR="/opt/tls_key_agent"
CONFIG_FILE="/etc/tls_key_agent/config.toml"
SERVICE_NAME="tls_key_agent"

# 验证结果统计
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# 测试函数
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_exit_code="${3:-0}"

    echo -n "测试: $test_name ... "

    if eval "$test_command" >/dev/null 2>&1; then
        local exit_code=$?
        if [[ $exit_code -eq $expected_exit_code ]]; then
            echo "✓"
            ((TESTS_PASSED++))
        else
            echo "✗ (退出码: $exit_code, 期望: $expected_exit_code)"
            ((TESTS_FAILED++))
        fi
    else
        echo "✗"
        ((TESTS_FAILED++))
    fi
}

# 检查文件存在性
check_files() {
    log_info "检查文件存在性..."

    run_test "二进制文件存在" "test -f '$INSTALL_DIR/tls_key_agent'"
    run_test "Hook库存在" "test -f '$INSTALL_DIR/libopenssl_hook.so'"
    run_test "eBPF程序存在" "test -f '$INSTALL_DIR/ebpf_monitor.o'"
    run_test "配置文件存在" "test -f '$CONFIG_FILE'"
    run_test "systemd服务文件存在" "test -f '/etc/systemd/system/$SERVICE_NAME.service'"
    run_test "日志轮转配置存在" "test -f '/etc/logrotate.d/$SERVICE_NAME'"
}

# 检查权限设置
check_permissions() {
    log_info "检查权限设置..."

    run_test "二进制文件可执行" "test -x '$INSTALL_DIR/tls_key_agent'"
    run_test "Hook库可读" "test -r '$INSTALL_DIR/libopenssl_hook.so'"
    run_test "配置文件可读" "test -r '$CONFIG_FILE'"

    if id "tls_agent" &>/dev/null; then
        run_test "服务用户存在" "id -u tls_agent >/dev/null"
    else
        log_warning "服务用户tls_agent不存在，跳过相关测试"
        ((TESTS_SKIPPED++))
    fi
}

# 检查服务状态
check_service() {
    log_info "检查服务状态..."

    if ! command -v systemctl &> /dev/null; then
        log_warning "systemd不可用，跳过服务检查"
        ((TESTS_SKIPPED++))
        return
    fi

    run_test "服务已启用" "systemctl is-enabled $SERVICE_NAME"
    run_test "服务正在运行" "systemctl is-active $SERVICE_NAME"

    # 检查服务日志
    if journalctl -u "$SERVICE_NAME" --since "1 minute ago" --quiet; then
        log_success "服务日志正常"
        ((TESTS_PASSED++))
    else
        log_warning "服务日志为空或不可访问"
        ((TESTS_SKIPPED++))
    fi
}

# 检查系统依赖
check_dependencies() {
    log_info "检查系统依赖..."

    # 检查基础工具
    run_test "gcc可用" "command -v gcc"
    run_test "make可用" "command -v make"
    run_test "openssl库可用" "pkg-config --exists openssl"

    # 检查eBPF支持
    local kernel_version=$(uname -r)
    local kernel_major=$(echo $kernel_version | cut -d. -f1)
    local kernel_minor=$(echo $kernel_version | cut -d. -f2)

    if [[ $kernel_major -ge 4 && $kernel_minor -ge 14 ]]; then
        log_success "内核版本支持eBPF: $kernel_version"
        ((TESTS_PASSED++))
    else
        log_warning "内核版本不支持eBPF: $kernel_version"
        ((TESTS_SKIPPED++))
    fi

    run_test "eBPF文件系统存在" "test -d /sys/fs/bpf"
    run_test "clang可用" "command -v clang"
    run_test "bpftool可用" "command -v bpftool"
}

# 检查功能测试
check_functionality() {
    log_info "检查功能测试..."

    # 测试命令行工具
    if [[ -x "$INSTALL_DIR/tls_key_agent" ]]; then
        run_test "帮助命令可用" "$INSTALL_DIR/tls_key_agent --help"
        run_test "版本命令可用" "$INSTALL_DIR/tls_key_agent --version"
    else
        log_warning "二进制文件不存在，跳过功能测试"
        ((TESTS_SKIPPED++))
        return
    fi

    # 测试配置文件解析
    run_test "配置文件可解析" "$INSTALL_DIR/tls_key_agent --config $CONFIG_FILE --dry-run"

    # 测试Hook库加载
    if [[ -f "$INSTALL_DIR/libopenssl_hook.so" ]]; then
        if objdump -T "$INSTALL_DIR/libopenssl_hook.so" 2>/dev/null | grep -q "SSL"; then
            log_success "Hook库包含TLS符号"
            ((TESTS_PASSED++))
        else
            log_warning "Hook库未检测到TLS符号"
            ((TESTS_SKIPPED++))
        fi
    fi

    # 测试eBPF程序
    if [[ -f "$INSTALL_DIR/ebpf_monitor.o" ]]; then
        if file "$INSTALL_DIR/ebpf_monitor.o" | grep -q "ELF 64-bit LSB relocatable"; then
            log_success "eBPF程序格式正确"
            ((TESTS_PASSED++))
        else
            log_error "eBPF程序格式不正确"
            ((TESTS_FAILED++))
        fi
    fi
}

# 检查网络功能
check_network() {
    log_info "检查网络功能..."

    # 检查TCP端口是否可用
    local tcp_port=9999
    if netstat -tuln 2>/dev/null | grep -q ":$tcp_port "; then
        log_success "TCP端口 $tcp_port 已监听"
        ((TESTS_PASSED++))
    else
        log_warning "TCP端口 $tcp_port 未监听"
        ((TESTS_SKIPPED++))
    fi

    # 测试本地连接
    if command -v nc &> /dev/null; then
        if echo "test" | nc localhost $tcp_port &>/dev/null; then
            log_success "本地TCP连接测试通过"
            ((TESTS_PASSED++))
        else
            log_warning "本地TCP连接测试失败"
            ((TESTS_SKIPPED++))
        fi
    else
        log_warning "netcat不可用，跳过网络测试"
        ((TESTS_SKIPPED++))
    fi
}

# 检查日志功能
check_logging() {
    log_info "检查日志功能..."

    local log_dir="/var/log/tls_key_agent"
    if [[ -d "$log_dir" ]]; then
        run_test "日志目录存在" "test -d '$log_dir'"

        if [[ -r "$log_dir" ]]; then
            run_test "日志目录可读" "test -r '$log_dir'"

            # 检查日志文件
            if find "$log_dir" -name "*.log" -type f | head -1 | xargs test -r 2>/dev/null; then
                log_success "日志文件可读"
                ((TESTS_PASSED++))
            else
                log_warning "日志文件不可读或不存在"
                ((TESTS_SKIPPED++))
            fi
        else
            log_warning "日志目录不可读"
            ((TESTS_FAILED++))
        fi
    else
        log_warning "日志目录不存在"
        ((TESTS_SKIPPED++))
    fi

    # 检查journal日志
    if command -v journalctl &> /dev/null; then
        if journalctl -u "$SERVICE_NAME" --lines=1 --quiet >/dev/null 2>&1; then
            log_success "journal日志可访问"
            ((TESTS_PASSED++))
        else
            log_warning "journal日志不可访问"
            ((TESTS_SKIPPED++))
        fi
    fi
}

# 检查性能指标
check_performance() {
    log_info "检查性能指标..."

    # 检查内存使用
    if pid=$(pgrep -f "$SERVICE_NAME" 2>/dev/null); then
        local memory_kb=$(ps -p "$pid" -o rss= | tr -d ' ')
        if [[ $memory_kb -gt 0 ]]; then
            if [[ $memory_kb -lt 50000 ]]; then  # < 50MB
                log_success "内存使用正常: ${memory_kb}KB"
                ((TESTS_PASSED++))
            else
                log_warning "内存使用较高: ${memory_kb}KB"
                ((TESTS_SKIPPED++))
            fi
        fi

        # 检查CPU使用
        local cpu_percent=$(ps -p "$pid" -o %cpu= | tr -d ' ')
        if [[ $(echo "$cpu_percent < 5.0" | bc -l 2>/dev/null || echo 1) -eq 1 ]]; then
            log_success "CPU使用正常: ${cpu_percent}%"
            ((TESTS_PASSED++))
        else
            log_warning "CPU使用较高: ${cpu_percent}%"
            ((TESTS_SKIPPED++))
        fi
    else
        log_warning "服务进程未运行，跳过性能检查"
        ((TESTS_SKIPPED++))
    fi
}

# 生成测试报告
generate_report() {
    echo
    echo "=========================================="
    echo "TLS Key Agent 安装验证报告"
    echo "=========================================="
    echo "测试通过: $TESTS_PASSED"
    echo "测试失败: $TESTS_FAILED"
    echo "测试跳过: $TESTS_SKIPPED"
    echo "总计测试: $((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))"
    echo

    if [[ $TESTS_FAILED -eq 0 ]]; then
        if [[ $TESTS_PASSED -gt 0 ]]; then
            log_success "所有测试通过！TLS Key Agent安装成功。"
            return 0
        else
            log_warning "没有执行任何测试，请检查安装状态。"
            return 1
        fi
    else
        log_error "有 $TESTS_FAILED 个测试失败。请检查安装配置。"
        return 1
    fi
}

# 显示帮助信息
show_help() {
    cat << EOF
TLS Key Agent 安装验证脚本

用法: $0 [选项]

选项:
    -h, --help              显示此帮助信息
    -d, --install-dir DIR   安装目录 (默认: $INSTALL_DIR)
    -c, --config FILE       配置文件路径 (默认: $CONFIG_FILE)
    -q, --quiet             安静模式，只显示错误和总结
    --skip-service          跳过服务检查
    --skip-network          跳过网络检查
    --skip-performance      跳过性能检查

示例:
    $0                      # 完整验证
    $0 -q                   # 安静模式
    $0 --skip-service       # 跳过服务检查
EOF
}

# 主函数
main() {
    local quiet_mode=false
    local skip_service=false
    local skip_network=false
    local skip_performance=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            --skip-service)
                skip_service=true
                shift
                ;;
            --skip-network)
                skip_network=true
                shift
                ;;
            --skip-performance)
                skip_performance=true
                shift
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ "$quiet_mode" != "true" ]]; then
        echo "=========================================="
        echo "TLS Key Agent 安装验证"
        echo "=========================================="
        echo "安装目录: $INSTALL_DIR"
        echo "配置文件: $CONFIG_FILE"
        echo
    fi

    # 运行各项检查
    check_files
    check_permissions
    check_dependencies

    if [[ "$skip_service" != "true" ]]; then
        check_service
    fi

    check_functionality

    if [[ "$skip_network" != "true" ]]; then
        check_network
    fi

    check_logging

    if [[ "$skip_performance" != "true" ]]; then
        check_performance
    fi

    # 生成报告
    generate_report
}

# 运行主函数
main "$@"