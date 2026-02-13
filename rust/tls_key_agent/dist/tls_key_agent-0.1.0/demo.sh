#!/bin/bash
# TLS Key Agent 完整演示脚本

set -e

echo "🚀 TLS Key Agent 完整演示"
echo "================================"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# 检查依赖
check_dependencies() {
    print_info "检查系统依赖..."

    if ! command -v python3 &> /dev/null; then
        print_error "Python3 未安装"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        print_error "curl 未安装"
        exit 1
    fi

    print_success "系统依赖检查完成"
}

# 编译项目
build_project() {
    print_info "编译 TLS Key Agent..."
    cd .. && cargo build --release && cd demo
    print_success "编译完成"
}

# 启动服务端
start_server() {
    print_info "启动 Demo 服务器..."

    # 检查端口是否被占用
    if lsof -i:8080 &> /dev/null; then
        print_warning "端口 8080 已被占用，尝试终止现有进程"
        pkill -f "demo_server.py" || true
        sleep 2
    fi

    if lsof -i:9999 &> /dev/null; then
        print_warning "端口 9999 已被占用，尝试终止现有进程"
        pkill -f "demo_server.py" || true
        sleep 2
    fi

    # 启动服务器
    python3 demo_server.py &
    SERVER_PID=$!
    echo $SERVER_PID > .demo_server.pid

    # 等待服务器启动
    sleep 3

    # 验证服务器是否启动
    if curl -s http://127.0.0.1:8080/health > /dev/null; then
        print_success "Demo 服务器已启动 (PID: $SERVER_PID)"
    else
        print_error "Demo 服务器启动失败"
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi
}

# 测试配置服务
test_config_service() {
    print_info "测试配置服务..."

    # 获取配置
    CONFIG_RESPONSE=$(curl -s "http://127.0.0.1:8080/config?agent_id=demo")

    if echo "$CONFIG_RESPONSE" | grep -q "config"; then
        print_success "配置服务正常工作"
        echo "配置大小: $(echo "$CONFIG_RESPONSE" | wc -c) 字节"
    else
        print_error "配置服务测试失败"
        echo "响应: $CONFIG_RESPONSE"
        return 1
    fi
}

# 启动 Agent
start_agent() {
    print_info "启动 TLS Key Agent..."

    # 清理现有进程
    pkill -f "tls_key_agent" 2>/dev/null || true
    sleep 2

    # 使用 demo 配置启动 agent
    sudo ../target/release/tls_key_agent --config demo_config.toml &
    AGENT_PID=$!
    echo $AGENT_PID > .demo_agent.pid

    # 等待 Agent 启动
    sleep 5

    print_success "TLS Key Agent 已启动 (PID: $AGENT_PID)"
}

# 生成测试流量
generate_traffic() {
    print_info "生成测试 TLS 流量..."

    # 等待几秒让 agent 初始化
    sleep 3

    print_info "测试 HTTPS 流量..."
    # HTTPS 流量测试
    timeout 10 curl -s https://www.baidu.com > /dev/null || true
    timeout 10 curl -s https://httpbin.org/get > /dev/null || true
    timeout 10 curl -s https://github.com > /dev/null || true

    print_info "测试 HTTP 流量..."
    # HTTP 流量测试
    timeout 5 curl -s http://httpbin.org/get > /dev/null || true
    timeout 5 curl -s http://www.example.com > /dev/null || true

    # 如果有其他工具，也可以测试
    if command -v wget &> /dev/null; then
        print_info "测试 wget HTTPS..."
        timeout 5 wget -q --spider https://www.baidu.com || true
    fi

    print_success "测试流量生成完成"
}

# 显示统计信息
show_stats() {
    print_info "获取服务统计..."

    # 获取健康状态
    HEALTH_RESPONSE=$(curl -s http://127.0.0.1:8080/health)
    if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
        REGISTERED_AGENTS=$(echo "$HEALTH_RESPONSE" | grep -o '"registered_agents":[0-9]*' | cut -d: -f2)
        print_success "服务健康状态: 正常"
        print_success "注册的 Agent 数量: $REGISTERED_AGENTS"
    else
        print_warning "无法获取健康状态"
    fi
}

# 清理函数
cleanup() {
    print_info "清理资源..."

    # 停止 agent
    if [ -f .demo_agent.pid ]; then
        AGENT_PID=$(cat .demo_agent.pid)
        if kill -0 $AGENT_PID 2>/dev/null; then
            sudo kill $AGENT_PID
            print_success "TLS Key Agent 已停止"
        fi
        rm -f .demo_agent.pid
    fi

    # 停止服务器
    if [ -f .demo_server.pid ]; then
        SERVER_PID=$(cat .demo_server.pid)
        if kill -0 $SERVER_PID 2>/dev/null; then
            kill $SERVER_PID
            print_success "Demo 服务器已停止"
        fi
        rm -f .demo_server.pid
    fi

    # 清理其他进程
    pkill -f "demo_server.py" 2>/dev/null || true
    pkill -f "tls_key_agent" 2>/dev/null || true

    print_success "清理完成"
}

# 设置信号处理
trap cleanup EXIT INT TERM

# 主函数
main() {
    echo "开始 TLS Key Agent 完整演示..."
    echo ""

    check_dependencies
    build_project
    start_server
    test_config_service
    start_agent
    generate_traffic
    show_stats

    echo ""
    print_info "演示正在运行中，按 Ctrl+C 停止..."
    print_info "你可以继续访问 HTTPS 网站来生成更多 TLS 密钥"
    print_info "查看服务器输出以实时显示捕获的密钥信息"

    # 保持运行直到用户中断
    while true; do
        sleep 10
        if ! pgrep -f "demo_server.py" > /dev/null; then
            print_error "Demo 服务器意外停止"
            exit 1
        fi
        if ! pgrep -f "tls_key_agent" > /dev/null; then
            print_warning "TLS Key Agent 可能已停止"
        fi
    done
}

# 显示帮助
show_help() {
    echo "TLS Key Agent 完整演示脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  start     启动完整演示"
    echo "  stop      停止所有服务"
    echo "  server    仅启动服务器"
    echo "  agent     仅启动 agent"
    echo "  traffic   仅生成测试流量"
    echo "  clean     清理资源"
    echo "  help      显示此帮助"
    echo ""
    echo "示例:"
    echo "  $0 start    # 启动完整演示"
    echo "  $0 stop     # 停止所有服务"
    echo "  $0 clean    # 清理资源"
}

# 处理命令行参数
case "${1:-start}" in
    "start")
        main
        ;;
    "stop")
        cleanup
        ;;
    "server")
        check_dependencies
        start_server
        ;;
    "agent")
        build_project
        start_agent
        ;;
    "traffic")
        generate_traffic
        ;;
    "clean")
        cleanup
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        echo "未知选项: $1"
        show_help
        exit 1
        ;;
esac