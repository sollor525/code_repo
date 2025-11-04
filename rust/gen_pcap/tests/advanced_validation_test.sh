#!/bin/bash

# 高级验证测试 - 重点验证二三四七层字段
# 专门验证TCP三次握手、HTTP内容、VLAN功能等关键特性

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 测试统计
TESTS_RUN=0
TESTS_PASSED=0

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_detail() {
    echo -e "${CYAN}[DETAIL]${NC} $1"
}

run_test() {
    ((TESTS_RUN++))
    log_info "运行测试 $TESTS_RUN: $1"
}

# 验证TCP三次握手
validate_tcp_handshake() {
    local pcap_file="$1"
    local test_name="$2"

    run_test "TCP三次握手验证 - $test_name"

    if command -v tcpdump >/dev/null 2>&1; then
        local packets=$(tcpdump -r "$pcap_file" -nn 2>/dev/null)
        local syn_count=$(echo "$packets" | grep -c "Flags \[S\]" || echo "0")
        local syn_ack_count=$(echo "$packets" | grep -c "Flags \[S.\]" || echo "0")
        local ack_count=$(echo "$packets" | grep -c "Flags \[.\]" | head -1)

        log_detail "SYN: $syn_count, SYN-ACK: $syn_ack_count, ACK: $ack_count"

        if [ "$syn_count" -gt 0 ] && [ "$syn_ack_count" -gt 0 ] && [ "$ack_count" -gt 0 ]; then
            log_pass "TCP三次握手完整 - $test_name"

            # 显示握手过程
            log_detail "握手过程:"
            echo "$packets" | head -3 | while read line; do
                log_detail "  $line"
            done
        else
            log_fail "TCP三次握手不完整 - $test_name"
        fi
    else
        log_detail "跳过TCP握手验证 (无tcpdump)"
    fi
}

# 验证HTTP内容
validate_http_content() {
    local pcap_file="$1"
    local test_name="$2"
    local expected_method="$3"

    run_test "HTTP内容验证 - $test_name"

    if command -v tcpdump >/dev/null 2>&1; then
        local http_content=$(tcpdump -r "$pcap_file" -nn -A 2>/dev/null)
        local request_count=$(echo "$http_content" | grep -c "$expected_method" || echo "0")
        local response_count=$(echo "$http_content" | grep -c "HTTP/1.1 200" || echo "0")

        log_detail "HTTP请求: $request_count, HTTP响应: $response_count"

        if [ "$request_count" -gt 0 ] && [ "$response_count" -gt 0 ]; then
            log_pass "HTTP内容完整 - $test_name"

            # 显示HTTP内容示例
            log_detail "HTTP请求示例:"
            echo "$http_content" | grep -A 3 "$expected_method" | head -4 | while read line; do
                if [ -n "$line" ]; then
                    log_detail "  $line"
                fi
            done
        else
            log_fail "HTTP内容不完整 - $test_name"
        fi
    else
        log_detail "跳过HTTP内容验证 (无tcpdump)"
    fi
}

# 验证VLAN标签
validate_vlan_tags() {
    local pcap_file="$1"
    local test_name="$2"
    local expected_vlan="$3"

    run_test "VLAN标签验证 - $test_name"

    if command -v tshark >/dev/null 2>&1; then
        local vlan_packets=$(tshark -r "$pcap_file" -Y "vlan" -T fields -e vlan.id 2>/dev/null)
        local vlan_count=$(echo "$vlan_packets" | grep -v "^$" | wc -l)

        log_detail "VLAN包数: $vlan_count"

        if [ "$vlan_count" -gt 0 ]; then
            log_pass "VLAN标签检测成功 - $test_name"

            log_detail "VLAN ID列表:"
            echo "$vlan_packets" | head -3 | while read vlan_id; do
                log_detail "  VLAN ID: $vlan_id"
            done
        else
            log_fail "未检测到VLAN标签 - $test_name"
        fi
    else
        log_detail "跳过VLAN验证 (无tshark)"
    fi
}

# 验证IP地址和端口
validate_network_layer() {
    local pcap_file="$1"
    local test_name="$2"

    run_test "网络层验证 - $test_name"

    if command -v tcpdump >/dev/null 2>&1; then
        local first_packet=$(tcpdump -r "$pcap_file" -nn -c 1 2>/dev/null)

        if [ -n "$first_packet" ]; then
            log_detail "网络层信息: $first_packet"

            # 简单验证IP和端口格式
            if echo "$first_packet" | grep -q "IP [0-9]"; then
                log_pass "IP地址格式正确 - $test_name"
            else
                log_fail "IP地址格式错误 - $test_name"
            fi

            if echo "$first_packet" | grep -q ":[0-9]\+ > [0-9]\+:"; then
                log_pass "端口格式正确 - $test_name"
            else
                log_fail "端口格式错误 - $test_name"
            fi
        else
            log_fail "无法读取网络包 - $test_name"
        fi
    fi
}

# 主测试函数
main() {
    echo "============================================"
    echo "      高级验证测试 - 二三四七层字段"
    echo "============================================"
    echo ""

    # 确保程序已编译
    if [ ! -f "./target/debug/gen_pcap" ]; then
        log_info "编译程序..."
        cargo build --quiet
    fi

    # 清理旧文件
    rm -f validation_*.pcap

    echo "开始高级验证测试..."
    echo ""

    # 测试1: 基础TCP流量
    echo "📍 测试1: 基础TCP流量 (3个会话)"
    ./target/debug/gen_pcap -n 3 -o validation_tcp_basic.pcap
    validate_tcp_handshake "validation_tcp_basic.pcap" "基础TCP"
    validate_network_layer "validation_tcp_basic.pcap" "基础TCP"
    echo ""

    # 测试2: 基础HTTP流量
    echo "📍 测试2: 基础HTTP流量 (2个会话)"
    ./target/debug/gen_pcap --http -n 2 -o validation_http_basic.pcap
    validate_tcp_handshake "validation_http_basic.pcap" "基础HTTP"
    validate_http_content "validation_http_basic.pcap" "基础HTTP" "GET"
    validate_network_layer "validation_http_basic.pcap" "基础HTTP"
    echo ""

    # 测试3: 多URI HTTP流量
    echo "📍 测试3: 多URI HTTP流量 (1个会话, 3个URI)"
    ./target/debug/gen_pcap --http -n 1 --http-uris '/api,/test,/health' -o validation_http_multi.pcap
    validate_tcp_handshake "validation_http_multi.pcap" "多URI HTTP"
    validate_http_content "validation_http_multi.pcap" "多URI HTTP" "GET"
    validate_network_layer "validation_http_multi.pcap" "多URI HTTP"
    echo ""

    # 测试4: 单层VLAN HTTP流量
    echo "📍 测试4: 单层VLAN HTTP流量 (VLAN ID: 100)"
    ./target/debug/gen_pcap --http -n 1 --vlan 100 -o validation_vlan_single.pcap
    validate_tcp_handshake "validation_vlan_single.pcap" "单层VLAN HTTP"
    validate_http_content "validation_vlan_single.pcap" "单层VLAN HTTP" "GET"
    validate_vlan_tags "validation_vlan_single.pcap" "单层VLAN HTTP" "100"
    validate_network_layer "validation_vlan_single.pcap" "单层VLAN HTTP"
    echo ""

    # 测试5: 双层VLAN HTTP流量
    echo "📍 测试5: 双层VLAN HTTP流量 (QinQ)"
    ./target/debug/gen_pcap --http -n 1 --qinq --outer-vlan 200 --inner-vlan 100 -o validation_vlan_qinq.pcap
    validate_tcp_handshake "validation_vlan_qinq.pcap" "双层VLAN HTTP"
    validate_http_content "validation_vlan_qinq.pcap" "双层VLAN HTTP" "GET"
    validate_vlan_tags "validation_vlan_qinq.pcap" "双层VLAN HTTP" "200"
    validate_network_layer "validation_vlan_qinq.pcap" "双层VLAN HTTP"
    echo ""

    # 测试6: 自定义端口HTTP流量
    echo "📍 测试6: 自定义端口HTTP流量 (端口8080)"
    ./target/debug/gen_pcap --http -n 1 -p 8080 -o validation_http_8080.pcap
    validate_tcp_handshake "validation_http_8080.pcap" "8080端口HTTP"
    validate_http_content "validation_http_8080.pcap" "8080端口HTTP" "GET"
    validate_network_layer "validation_http_8080.pcap" "8080端口HTTP"
    echo ""

    # 测试7: YAML模板HTTP流量
    echo "📍 测试7: YAML模板HTTP流量"
    cat > validation_template.yaml << 'EOF'
metadata:
  name: "验证测试模板"
  description: "用于验证测试的HTTP模板"
  version: "1.0"

network:
  src_mac: "aa:bb:cc:dd:ee:ff"
  dst_mac: "11:22:33:44:55:66"

sessions:
  - name: "test_session"
    repeat: 1
    connection:
      src:
        ip: "192.168.100.10"
        port: 12345
      dst:
        ip: "10.0.0.50"
        port: 80
    session_type:
      type: "Tcp"
      ports: [80]
      duration_ms: 3000
    application:
      protocol: "Http"
      requests:
        - method: "GET"
          uri: "/validation/test"
          headers:
            Host: "validation.test.com"
            User-Agent: "ValidationClient/1.0"
      responses:
        - status_code: 200
          headers:
            Content-Type: "application/json"
          body: '{"validation": "success", "test": "passed"}'

defaults:
  timing:
    packet_delay_ms: 10
EOF

    ./target/debug/gen_pcap -t validation_template.yaml -o validation_yaml.pcap
    validate_tcp_handshake "validation_yaml.pcap" "YAML模板HTTP"
    validate_http_content "validation_yaml.pcap" "YAML模板HTTP" "GET"
    validate_network_layer "validation_yaml.pcap" "YAML模板HTTP"
    echo ""

    # 测试结果汇总
    echo "============================================"
    echo "              测试结果汇总"
    echo "============================================"
    echo ""
    echo "总测试数: $TESTS_RUN"
    echo "通过测试: $TESTS_PASSED"
    echo "失败测试: $((TESTS_RUN - TESTS_PASSED))"
    echo ""

    if [ $TESTS_PASSED -eq $TESTS_RUN ]; then
        echo -e "${GREEN}🎉 所有测试通过！系统功能完全正常！${NC}"
        exit_code=0
    else
        echo -e "${YELLOW}⚠️  有 $((TESTS_RUN - TESTS_PASSED)) 个测试未通过${NC}"
        exit_code=1
    fi

    echo ""
    echo "生成的验证文件:"
    ls -lh validation_*.pcap 2>/dev/null | while read line; do
        echo "  $line"
    done

    echo ""
    echo "文件包数统计:"
    for file in validation_*.pcap; do
        if [ -f "$file" ]; then
            count=$(tcpdump -r "$file" -nn 2>/dev/null | wc -l)
            size=$(stat -c%s "$file" 2>/dev/null || echo "0")
            echo "  $file: $count 个包, ${size} 字节"
        fi
    done

    echo ""
    echo "许可证状态:"
    ./target/debug/gen_pcap --license-status

    # 清理文件
    echo ""
    log_info "清理验证文件..."
    rm -f validation_*.pcap validation_template.yaml

    exit $exit_code
}

main "$@"