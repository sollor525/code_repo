#!/bin/bash

# TLS Key Agent eBPF + 动态注入组合部署脚本
# 作者: sollor525@hotmail.com
# 版本: 0.1.0
# 日期: 2023-11-05

set -e

# 配置变量
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
HOOK_LIBRARY="$PROJECT_DIR/target/release/libopenssl_hook.so"
INJECTOR_BIN="$PROJECT_DIR/target/release/simple_injector"
CONFIG_FILE="$PROJECT_DIR/ebpf_config.toml"
LOG_FILE="/var/log/tls_key_agent/ebpf_combo.log"
PID_FILE="/var/run/tls_key_agent/ebpf_combo.pid"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}" | tee -a "$LOG_FILE"
}

# 检查依赖
check_dependencies() {
    log "检查依赖..."

    # 检查是否为root用户
    if [[ $EUID -ne 0 ]]; then
        error "此脚本需要root权限运行"
        exit 1
    fi

    # 检查必要的命令
    local deps=("gdb" "bpftool" "clang" "llvm" "libbpf-dev")
    local missing=()

    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "缺少依赖: ${missing[*]}"
        info "请安装缺少的依赖:"
        info "  Ubuntu/Debian: sudo apt-get install ${missing[*]}"
        info "  CentOS/RHEL: sudo yum install ${missing[*]}"
        exit 1
    fi

    # 检查文件是否存在
    if [[ ! -f "$HOOK_LIBRARY" ]]; then
        error "Hook库文件不存在: $HOOK_LIBRARY"
        info "请先编译项目: cargo build --release"
        exit 1
    fi

    if [[ ! -f "$INJECTOR_BIN" ]]; then
        error "注入器二进制不存在: $INJECTOR_BIN"
        info "请先编译项目: cargo build --release"
        exit 1
    fi

    log "依赖检查完成"
}

# 创建必要的目录
create_directories() {
    log "创建必要的目录..."
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$PID_FILE")"
    mkdir -p "/tmp/tls_key_agent"
}

# 编译eBPF程序
compile_ebpf() {
    log "编译eBPF程序..."

    cd "$PROJECT_DIR"

    # 编译eBPF对象文件
    clang -O2 -target bpf -c src/ebpf_monitor.c -o ebpf_monitor.o

    # 使用bpftool加载eBPF程序
    if bpftool prog show | grep -q "tls_monitor"; then
        info "eBPF程序已加载，跳过编译"
        return 0
    fi

    # 加载eBPF程序
    bpftool prog load ebpf_monitor.o /sys/fs/bpf/tls_monitor

    if [[ $? -eq 0 ]]; then
        log "eBPF程序编译和加载成功"
    else
        error "eBPF程序加载失败"
        exit 1
    fi
}

# 启动eBPF监控
start_ebpf_monitor() {
    log "启动eBPF监控..."

    # 启动eBPF事件监听器
    if pgrep -f "tls_key_agent_ebpf" > /dev/null; then
        warn "eBPF监控器已在运行"
        return 0
    fi

    # 创建eBPF事件监听器
    cat > /tmp/tls_key_agent/ebpf_listener.py << 'EOF'
#!/usr/bin/env python3
import sys
import os
import json
from bcc import BPF

# eBPF程序
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct tls_event {
    u32 pid;
    u64 timestamp;
    char comm[16];
};

BPF_PERF_OUTPUT(events);

SEC("kprobe/SSL_write")
int trace_ssl_write(struct pt_regs *ctx) {
    struct tls_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""

# 加载eBPF程序
b = BPF(text=bpf_text)

# 事件处理函数
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"TLS Event: PID={event.pid}, Comm={event.comm.decode()}, Timestamp={event.timestamp}")

# 附加事件处理函数
b["events"].open_perf_buffer(print_event)

print("开始监控TLS事件...")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break
EOF

    chmod +x /tmp/tls_key_agent/ebpf_listener.py

    # 在后台启动eBPF监听器
    nohup python3 /tmp/tls_key_agent/ebpf_listener.py > "$LOG_FILE.ebpf" 2>&1 &
    echo $! > "$PID_FILE.ebpf"

    log "eBPF监控器已启动"
}

# 发现TLS进程
discover_tls_processes() {
    log "发现系统中的TLS进程..."

    info "当前系统中的TLS进程:"
    "$INJECTOR_BIN" discover --format table

    # 保存到文件
    "$INJECTOR_BIN" discover --format json > "/tmp/tls_key_agent/discovered_processes.json"

    log "进程发现完成"
}

# 动态注入Hook
inject_hooks() {
    log "开始动态注入Hook..."

    # 显示将要注入的进程
    info "将要注入的TLS进程:"
    "$INJECTOR_BIN" discover

    echo
    warn "即将开始实际注入，请确认要继续吗？(y/N)"
    read -r response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        # 执行实际注入 - 获取所有TLS进程并逐个注入
        info "开始实际注入..."

        # 获取所有未Hook的TLS进程PID
        for pid in $($INJECTOR_BIN discover --format json | \
            jq -r '.[] | select(.uses_tls == true and .is_hooked == false) | .pid'); do
            info "注入进程 $pid..."
            "$INJECTOR_BIN" inject \
                --pid $pid \
                --library "$HOOK_LIBRARY" \
                2>&1 | tee -a "$LOG_FILE.inject"
        done

        log "Hook注入完成"
    else
        warn "用户取消注入操作"
    fi
}

# 启动持续监控
start_continuous_monitor() {
    log "启动持续监控模式..."

    # 启动注入器的监控模式
    nohup "$INJECTOR_BIN" monitor \
        --library "$HOOK_LIBRARY" \
        --interval 5 \
        > "$LOG_FILE.monitor" 2>&1 &

    local monitor_pid=$!
    echo $monitor_pid > "$PID_FILE.monitor"

    log "持续监控已启动 (PID: $monitor_pid)"
}

# 检查注入状态
check_injection_status() {
    log "检查Hook注入状态..."

    # 重新发现进程
    info "当前Hook注入状态:"
    "$INJECTOR_BIN" discover --format table | grep -E "(PID|.*Hooked)"

    # 统计信息
    local total_tls=$("$INJECTOR_BIN" discover --format json 2>/dev/null | \
        jq '.[] | select(.uses_tls == true) | .pid' | wc -l)
    local hooked=$("$INJECTOR_BIN" discover --format json 2>/dev/null | \
        jq '.[] | select(.is_hooked == true) | .pid' | wc -l)

    info "统计信息:"
    info "  TLS进程总数: $total_tls"
    info "  已Hook进程数: $hooked"
    info "  Hook覆盖率: $(( hooked * 100 / total_tls ))%"
}

# 清理资源
cleanup() {
    log "清理资源..."

    # 停止监控进程
    if [[ -f "$PID_FILE.monitor" ]]; then
        local monitor_pid=$(cat "$PID_FILE.monitor")
        if kill -0 "$monitor_pid" 2>/dev/null; then
            kill "$monitor_pid"
            log "已停止监控进程 (PID: $monitor_pid)"
        fi
        rm -f "$PID_FILE.monitor"
    fi

    if [[ -f "$PID_FILE.ebpf" ]]; then
        local ebpf_pid=$(cat "$PID_FILE.ebpf")
        if kill -0 "$ebpf_pid" 2>/dev/null; then
            kill "$ebpf_pid"
            log "已停止eBPF监听器 (PID: $ebpf_pid)"
        fi
        rm -f "$PID_FILE.ebpf"
    fi

    # 卸载eBPF程序
    if bpftool prog show | grep -q "tls_monitor"; then
        bpftool prog detach name trace_ssl_write kprobe
        log "已卸载eBPF程序"
    fi

    # 清理临时文件
    rm -rf /tmp/tls_key_agent/ebpf_listener.py
    rm -f /tmp/tls_key_agent/discovered_processes.json

    log "资源清理完成"
}

# 显示帮助
show_help() {
    cat << EOF
TLS Key Agent eBPF + 动态注入组合部署脚本

用法: $0 [选项]

选项:
    start       完整部署（包含所有步骤）
    discover    仅发现TLS进程
    inject      仅执行Hook注入
    monitor     仅启动持续监控
    status      检查注入状态
    cleanup     清理所有资源
    help        显示此帮助信息

示例:
    $0 start                    # 完整部署
    $0 discover                 # 发现TLS进程
    $0 inject                   # 注入Hook
    $0 monitor                  # 启动监控
    $0 status                   # 检查状态
    $0 cleanup                  # 清理资源

注意: 此脚本需要root权限运行

EOF
}

# 完整部署
full_deployment() {
    log "开始完整部署eBPF + 动态注入组合..."

    check_dependencies
    create_directories
    compile_ebpf
    start_ebpf_monitor
    discover_tls_processes
    inject_hooks
    start_continuous_monitor
    check_injection_status

    log "完整部署完成！"
    info "日志文件: $LOG_FILE"
    info "PID文件: $PID_FILE"
    info "使用 '$0 status' 检查状态"
    info "使用 '$0 cleanup' 清理资源"
}

# 信号处理
trap cleanup EXIT INT TERM

# 主程序
main() {
    case "${1:-start}" in
        "start")
            full_deployment
            ;;
        "discover")
            check_dependencies
            discover_tls_processes
            ;;
        "inject")
            check_dependencies
            inject_hooks
            ;;
        "monitor")
            check_dependencies
            start_continuous_monitor
            ;;
        "status")
            check_injection_status
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

# 执行主程序
main "$@"