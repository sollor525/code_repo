#!/bin/bash

# HTTP流量集成测试脚本
# 测试各种HTTP流量生成方式，包括命令行参数和YAML模板

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 测试结果统计
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED_TESTS++))
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED_TESTS++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 测试函数
run_test() {
    local test_name="$1"
    local test_command="$2"
    local output_file="$3"
    local expected_min_packets="$4"
    local expected_max_packets="$5"

    ((TOTAL_TESTS++))
    log_info "运行测试: $test_name"
    log_info "命令: $test_command"

    # 运行命令
    if eval "$test_command" > /dev/null 2>&1; then
        # 检查文件是否存在
        if [ -f "$output_file" ]; then
            # 检查文件大小
            local file_size=$(stat -c%s "$output_file" 2>/dev/null || stat -f%z "$output_file" 2>/dev/null || echo "0")
            if [ "$file_size" -gt 0 ]; then
                # 使用tcpdump检查数据包数量（如果可用）
                local packet_count=0
                if command -v tcpdump >/dev/null 2>&1; then
                    packet_count=$(tcpdump -r "$output_file" -nn 2>/dev/null | wc -l || echo "0")
                else
                    # 如果没有tcpdump，使用文件大小估算
                    packet_count=$((file_size / 62))  # 估算每个包约62字节
                fi

                log_info "生成文件: $output_file (大小: ${file_size}字节, 估算包数: ${packet_count})"

                # 检查包数是否在预期范围内
                if [ "$packet_count" -ge "$expected_min_packets" ] && [ "$packet_count" -le "$expected_max_packets" ]; then
                    log_success "$test_name - 包数: $packet_count (预期: $expected_min_packets-$expected_max_packets)"
                else
                    log_error "$test_name - 包数不符合预期: $packet_count (预期: $expected_min_packets-$expected_max_packets)"
                fi
            else
                log_error "$test_name - 生成文件为空"
            fi
        else
            log_error "$test_name - 未生成输出文件"
        fi
    else
        log_error "$test_name - 命令执行失败"
    fi
}

# 创建YAML模板函数
create_yaml_template() {
    local template_file="$1"
    local content="$2"
    echo "$content" > "$template_file"
    log_info "创建YAML模板: $template_file"
}

# 清理函数
cleanup() {
    log_info "清理测试文件..."
    rm -f *.pcap *.yaml test_output_*
}

# 主测试函数
main() {
    echo "=========================================="
    echo "     HTTP流量集成测试套件"
    echo "=========================================="

    # 确保程序已编译
    if [ ! -f "./target/debug/gen_pcap" ]; then
        log_info "编译程序..."
        cargo build --quiet
    fi

    # 清理旧文件
    cleanup

    echo ""
    log_info "开始命令行参数测试..."
    echo "=========================================="

    # 测试1: 基础HTTP流量
    run_test "基础HTTP流量" \
        "./target/debug/gen_pcap --http -n 3 -o test_output_basic_http.pcap" \
        "test_output_basic_http.pcap" \
        "15" "20"

    # 测试2: 多URI HTTP流量
    run_test "多URI HTTP流量" \
        "./target/debug/gen_pcap --http -n 2 --http-uris '/api,/test,/health,/status' -o test_output_multi_uri.pcap" \
        "test_output_multi_uri.pcap" \
        "40" "50"

    # 测试3: 自定义Host
    run_test "自定义Host HTTP流量" \
        "./target/debug/gen_pcap --http -n 4 --http-host 'api.example.com' -o test_output_custom_host.pcap" \
        "test_output_custom_host.pcap" \
        "20" "25"

    # 测试4: 不同端口HTTP流量
    run_test "8080端口HTTP流量" \
        "./target/debug/gen_pcap --http -n 3 -p 8080 -o test_output_port_8080.pcap" \
        "test_output_port_8080.pcap" \
        "15" "20"

    # 测试5: 随机源IP HTTP流量
    run_test "随机源IP HTTP流量" \
        "./target/debug/gen_pcap --http -n 2 -s random -o test_output_random_src.pcap" \
        "test_output_random_src.pcap" \
        "10" "15"

    # 测试6: 随机目标IP HTTP流量
    run_test "随机目标IP HTTP流量" \
        "./target/debug/gen_pcap --http -n 2 -d random -o test_output_random_dst.pcap" \
        "test_output_random_dst.pcap" \
        "10" "15"

    # 测试7: 随机端口HTTP流量
    run_test "随机端口HTTP流量" \
        "./target/debug/gen_pcap --http -n 2 --src-port random -p random -o test_output_random_port.pcap" \
        "test_output_random_port.pcap" \
        "10" "15"

    # 测试8: 大量HTTP会话
    run_test "大量HTTP会话(50个)" \
        "./target/debug/gen_pcap --http -n 50 -o test_output_large_sessions.pcap" \
        "test_output_large_sessions.pcap" \
        "250" "300"

    echo ""
    log_info "开始YAML模板测试..."
    echo "=========================================="

    # YAML模板测试1: 基础HTTP模板
    create_yaml_template "test_basic_http.yaml" '
metadata:
  name: "基础HTTP流量测试"
  description: "测试基本的HTTP GET请求"
  version: "1.0"

network:
  src_ip: "192.168.1.100"
  dst_ip: "10.0.0.50"
  src_port: "30000-35000"
  dst_port: "80"

sessions:
  - count: 3
    application:
      type: "http"
      config:
        host: "web.example.com"
        uris: ["/", "/index.html", "/about"]
        methods: ["GET"]

defaults:
  timing:
    packet_delay_ms: 10
  tcp:
    window_size: 8192
'

    run_test "YAML模板 - 基础HTTP" \
        "./target/debug/gen_pcap -t test_basic_http.yaml -o test_output_yaml_basic.pcap" \
        "test_output_yaml_basic.pcap" \
        "24" "30"

    # YAML模板测试2: 复杂HTTP场景
    create_yaml_template "test_complex_http.yaml" '
metadata:
  name: "复杂HTTP流量测试"
  description: "测试多种HTTP方法和场景"
  version: "1.0"

network:
  src_ip: "172.16.0.10"
  dst_ip: "192.168.100.20"
  src_port: "40000-45000"
  dst_port: "80"

sessions:
  - count: 2
    application:
      type: "http"
      config:
        host: "api.service.com"
        uris: ["/api/v1/users", "/api/v1/data"]
        methods: ["GET"]
        headers:
          User-Agent: "TestClient/1.0"
          Accept: "application/json"

  - count: 2
    application:
      type: "http"
      config:
        host: "cdn.assets.com"
        uris: ["/images/logo.png", "/css/style.css"]
        methods: ["GET"]
        headers:
          User-Agent: "Mozilla/5.0"
          Accept: "*/*"

defaults:
  timing:
    packet_delay_ms: 5
  tcp:
    window_size: 16384
'

    run_test "YAML模板 - 复杂HTTP场景" \
        "./target/debug/gen_pcap -t test_complex_http.yaml -o test_output_yaml_complex.pcap" \
        "test_output_yaml_complex.pcap" \
        "32" "40"

    # YAML模板测试3: 微服务场景
    create_yaml_template "test_microservices.yaml" '
metadata:
  name: "微服务HTTP流量测试"
  description: "模拟微服务架构中的HTTP通信"
  version: "1.0"

network:
  src_ip: "10.0.1.50"
  dst_ip: "10.0.2.100"
  src_port: "50000-55000"
  dst_port: "80"

sessions:
  - count: 3
    application:
      type: "http"
      config:
        host: "user-service.micro.local"
        uris: ["/users/123", "/users/456", "/users/789"]
        methods: ["GET"]
        headers:
          Authorization: "Bearer token123"
          Content-Type: "application/json"

  - count: 2
    application:
      type: "http"
      config:
        host: "order-service.micro.local"
        uris: ["/orders", "/orders/status"]
        methods: ["POST", "GET"]
        headers:
          Authorization: "Bearer token456"
          Content-Type: "application/json"
        post_body: '{"product_id": 123, "quantity": 2}'

defaults:
  timing:
    packet_delay_ms: 2
  tcp:
    window_size: 32768
'

    run_test "YAML模板 - 微服务场景" \
        "./target/debug/gen_pcap -t test_microservices.yaml -o test_output_yaml_microservices.pcap" \
        "test_output_yaml_microservices.pcap" \
        "40" "50"

    # YAML模板测试4: 带VLAN的HTTP流量
    create_yaml_template "test_vlan_http.yaml" '
metadata:
  name: "VLAN HTTP流量测试"
  description: "测试带有VLAN标签的HTTP流量"
  version: "1.0"

network:
  src_ip: "192.168.10.20"
  dst_ip: "192.168.20.30"
  src_port: "60000-61000"
  dst_port: "80"

sessions:
  - count: 2
    application:
      type: "http"
      config:
        host: "secure.company.com"
        uris: ["/secure/api", "/dashboard"]
        methods: ["GET"]
        headers:
          X-Forwarded-For: "client.proxy.local"
          X-Real-IP: "203.0.113.1"

vlan:
  tags:
    - vlan_id: 100
      priority: 3
      dei: false

defaults:
  timing:
    packet_delay_ms: 15
  tcp:
    window_size: 65535
'

    run_test "YAML模板 - VLAN HTTP流量" \
        "./target/debug/gen_pcap -t test_vlan_http.yaml -o test_output_yaml_vlan.pcap" \
        "test_output_yaml_vlan.pcap" \
        "14" "20"

    echo ""
    log_info "开始边界条件和错误处理测试..."
    echo "=========================================="

    # 测试9: 空URI列表
    run_test "空URI列表(应使用默认)" \
        "./target/debug/gen_pcap --http -n 2 --http-uris '' -o test_output_empty_uris.pcap" \
        "test_output_empty_uris.pcap" \
        "10" "15"

    # 测试10: 单个会话多URI
    run_test "单个会话多URI" \
        "./target/debug/gen_pcap --http -n 1 --http-uris '/a,/b,/c,/d,/e' -o test_output_single_multi_uri.pcap" \
        "test_output_single_multi_uri.pcap" \
        "13" "18"

    # 测试11: 极限会话数测试
    run_test "极限会话数测试(200个)" \
        "./target/debug/gen_pcap --http -n 200 -o test_output极限_sessions.pcap" \
        "test_output极限_sessions.pcap" \
        "1000" "1100"

    echo ""
    echo "=========================================="
    echo "             测试结果汇总"
    echo "=========================================="
    echo -e "总测试数: ${BLUE}$TOTAL_TESTS${NC}"
    echo -e "通过测试: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "失败测试: ${RED}$FAILED_TESTS${NC}"

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}✅ 所有测试通过！${NC}"
        exit_code=0
    else
        echo -e "\n${RED}❌ 有 $FAILED_TESTS 个测试失败${NC}"
        exit_code=1
    fi

    echo ""
    log_info "生成文件列表:"
    ls -la *.pcap 2>/dev/null | head -10 || log_warning "没有找到PCAP文件"

    echo ""
    log_info "许可证状态:"
    ./target/debug/gen_pcap --license-status

    # 清理（可选择保留文件用于调试）
    if [ "$1" != "--keep-files" ]; then
        cleanup
    fi

    exit $exit_code
}

# 信号处理
trap cleanup EXIT

# 运行主函数
main "$@"