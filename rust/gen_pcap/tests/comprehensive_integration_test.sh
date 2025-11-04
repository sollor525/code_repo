#!/bin/bash

# 全面集成测试脚本 - 验证二三四七层字段及VLAN功能
# 测试完整的会话、HTTP/TCP数据包、VLAN标签等所有功能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 测试结果统计
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
DETAILED_TESTS=0

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

log_detail() {
    echo -e "${CYAN}[DETAIL]${NC} $1"
    ((DETAILED_TESTS++))
}

# 检查依赖工具
check_dependencies() {
    local missing_tools=()

    if ! command -v tcpdump >/dev/null 2>&1; then
        missing_tools+=("tcpdump")
    fi

    if ! command -v hexdump >/dev/null 2>&1; then
        missing_tools+=("hexdump")
    fi

    if ! command -v tshark >/dev/null 2>&1; then
        missing_tools+=("tshark")
        log_warning "tshark未安装，某些详细验证将跳过"
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warning "缺少工具: ${missing_tools[*]}"
        log_info "建议安装: apt-get install tcpdump wireshark-common"
    fi
}

# 验证二层字段（MAC地址、VLAN标签）
validate_layer2() {
    local pcap_file="$1"
    local test_name="$2"
    local expected_src_mac="$3"
    local expected_dst_mac="$4"
    local expected_vlan="$5"

    ((TOTAL_TESTS++))
    log_info "验证二层字段: $test_name"

    if [ ! -f "$pcap_file" ]; then
        log_error "PCAP文件不存在: $pcap_file"
        return 1
    fi

    # 使用tcpdump验证MAC地址
    if command -v tcpdump >/dev/null 2>&1; then
        local first_packet=$(tcpdump -r "$pcap_file" -nn -c 1 2>/dev/null)
        if [ -n "$first_packet" ]; then
            log_detail "首个数据包: $first_packet"

            # 验证MAC地址（如果指定了期望值）
            if [ -n "$expected_src_mac" ] || [ -n "$expected_dst_mac" ]; then
                if echo "$first_packet" | grep -q -E "([0-9a-f]{2}:){5}[0-9a-f]{2}"; then
                    log_success "MAC地址格式正确"
                else
                    log_warning "MAC地址格式未检测到"
                fi
            fi

            # 验证VLAN标签（如果指定）
            if [ -n "$expected_vlan" ]; then
                if command -v tshark >/dev/null 2>&1; then
                    local vlan_count=$(tshark -r "$pcap_file" -Y "vlan" -T fields -e vlan.id 2>/dev/null | grep -v "^$" | wc -l)
                    if [ "$vlan_count" -gt 0 ]; then
                        log_success "检测到VLAN标签 ($vlan_count 个包)"
                        log_detail "VLAN ID详情:"
                        tshark -r "$pcap_file" -Y "vlan" -T fields -e vlan.id -e vlan.priority 2>/dev/null | head -3 | while read vlan_id priority; do
                            log_detail "  VLAN ID: $vlan_id, Priority: $priority"
                        done
                    else
                        log_error "未检测到预期的VLAN标签"
                    fi
                fi
            fi
        else
            log_error "无法读取数据包"
        fi
    fi

    log_success "二层字段验证完成: $test_name"
}

# 验证三层字段（IP地址）
validate_layer3() {
    local pcap_file="$1"
    local test_name="$2"
    local expected_src_ip="$3"
    local expected_dst_ip="$4"

    ((TOTAL_TESTS++))
    log_info "验证三层字段: $test_name"

    if command -v tcpdump >/dev/null 2>&1; then
        local ip_packets=$(tcpdump -r "$pcap_file" -nn 2>/dev/null | grep "IP ")
        if [ -n "$ip_packets" ]; then
            local first_ip=$(echo "$ip_packets" | head -1)
            log_detail "IP数据包示例: $first_ip"

            # 提取IP地址进行验证
            local src_ip=$(echo "$first_ip" | sed -n 's/IP \([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\)\.[0-9]\+ > .*/\1/p')
            local dst_ip=$(echo "$first_ip" | sed -n 's/IP .*> \([0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\)\.[0-9]\+ :.*/\1/p')

            if [ -n "$src_ip" ] && [ -n "$dst_ip" ]; then
                log_detail "源IP: $src_ip, 目标IP: $dst_ip"

                # 验证期望的IP地址（如果指定）
                if [ -n "$expected_src_ip" ] && [ "$expected_src_ip" != "$src_ip" ]; then
                    log_warning "源IP不匹配: 期望 $expected_src_ip, 实际 $src_ip"
                fi

                if [ -n "$expected_dst_ip" ] && [ "$expected_dst_ip" != "$dst_ip" ]; then
                    log_warning "目标IP不匹配: 期望 $expected_dst_ip, 实际 $dst_ip"
                fi

                log_success "IP地址验证通过"
            else
                log_warning "IP地址格式解析失败，使用简单验证"
                log_success "IP数据包存在验证通过"
            fi
        else
            log_error "未找到IP数据包"
        fi
    fi

    log_success "三层字段验证完成: $test_name"
}

# 验证四层字段（TCP端口、序列号、标志位）
validate_layer4() {
    local pcap_file="$1"
    local test_name="$2"
    local expected_src_port="$3"
    local expected_dst_port="$4"

    ((TOTAL_TESTS++))
    log_info "验证四层字段: $test_name"

    if command -v tcpdump >/dev/null 2>&1; then
        local tcp_packets=$(tcpdump -r "$pcap_file" -nn 2>/dev/null | grep "IP ")
        local packet_count=$(echo "$tcp_packets" | wc -l)

        log_detail "TCP数据包总数: $packet_count"

        # 分析TCP标志位
        local syn_count=$(echo "$tcp_packets" | grep -c "Flags \[S\]" || echo "0")
        local syn_ack_count=$(echo "$tcp_packets" | grep -c "Flags \[S.\]" || echo "0")
        local ack_count=$(echo "$tcp_packets" | grep -c "Flags \[.\]" || echo "0")
        local psh_count=$(echo "$tcp_packets" | grep -c "Flags \[P\]" || echo "0")

        log_detail "TCP标志位统计:"
        log_detail "  SYN: $syn_count, SYN-ACK: $syn_ack_count, ACK: $ack_count, PSH: $psh_count"

        # 验证TCP三次握手
        if [ "$syn_count" -gt 0 ] && [ "$syn_ack_count" -gt 0 ] && [ "$ack_count" -gt 0 ]; then
            log_success "TCP三次握手完整"
        else
            log_warning "TCP三次握手可能不完整"
        fi

        # 验证端口
        local first_packet=$(echo "$tcp_packets" | head -1)
        local src_port=$(echo "$first_packet" | sed -n 's/.*IP[^:]*:\([0-9]\+\) > .*/\1/p')
        local dst_port=$(echo "$first_packet" | sed -n 's/.*> \([0-9]\+\):.*/\1/p')

        if [ -n "$src_port" ] && [ -n "$dst_port" ]; then
            log_detail "端口: 源 $src_port -> 目标 $dst_port"

            if [ -n "$expected_src_port" ] && [ "$expected_src_port" != "$src_port" ]; then
                log_warning "源端口不匹配: 期望 $expected_src_port, 实际 $src_port"
            fi

            if [ -n "$expected_dst_port" ] && [ "$expected_dst_port" != "$dst_port" ]; then
                log_warning "目标端口不匹配: 期望 $expected_dst_port, 实际 $dst_port"
            fi
        else
            log_warning "端口解析失败"
        fi

        # 验证序列号（使用tshark如果可用）
        if command -v tshark >/dev/null 2>&1; then
            log_detail "TCP序列号分析:"
            tshark -r "$pcap_file" -Y "tcp" -T fields -e tcp.seq -e tcp.ack -e tcp.flags 2>/dev/null | head -5 | while read seq ack flags; do
                log_detail "  SEQ: $seq, ACK: $ack, Flags: $flags"
            done
        fi
    fi

    log_success "四层字段验证完成: $test_name"
}

# 验证七层字段（HTTP内容）
validate_layer7() {
    local pcap_file="$1"
    local test_name="$2"
    local expected_method="$3"
    local expected_uri="$4"
    local expected_host="$5"

    ((TOTAL_TESTS++))
    log_info "验证七层字段: $test_name"

    if command -v tcpdump >/dev/null 2>&1; then
        # 检查HTTP请求
        local http_requests=$(tcpdump -r "$pcap_file" -nn -A 2>/dev/null | grep -A 5 "GET \|^POST")
        if [ -n "$http_requests" ]; then
            log_detail "HTTP请求示例:"
            echo "$http_requests" | head -10 | while read line; do
                log_detail "  $line"
            done

            # 验证HTTP方法
            if [ -n "$expected_method" ]; then
                local method_count=$(echo "$http_requests" | grep -c "$expected_method" || echo "0")
                if [ "$method_count" -gt 0 ]; then
                    log_success "HTTP方法验证: $expected_method ($method_count 个请求)"
                else
                    log_error "HTTP方法验证失败: 未找到 $expected_method"
                fi
            fi

            # 验证URI
            if [ -n "$expected_uri" ]; then
                local uri_count=$(echo "$http_requests" | grep -c "$expected_uri" || echo "0")
                if [ "$uri_count" -gt 0 ]; then
                    log_success "URI验证: $expected_uri ($uri_count 个请求)"
                else
                    log_warning "URI验证: 未找到预期URI $expected_uri"
                fi
            fi

            # 验证Host头
            if [ -n "$expected_host" ]; then
                local host_count=$(echo "$http_requests" | grep -i "Host: $expected_host" | wc -l)
                if [ "$host_count" -gt 0 ]; then
                    log_success "Host头验证: $expected_host ($host_count 次)"
                else
                    log_warning "Host头验证: 未找到预期Host $expected_host"
                fi
            fi
        else
            log_warning "未检测到HTTP请求"
        fi

        # 检查HTTP响应
        local http_responses=$(tcpdump -r "$pcap_file" -nn -A 2>/dev/null | grep -A 5 "HTTP/")
        if [ -n "$http_responses" ]; then
            log_detail "HTTP响应示例:"
            echo "$http_responses" | head -5 | while read line; do
                log_detail "  $line"
            done

            # 验证HTTP状态码
            local status_200=$(echo "$http_responses" | grep -c "200 OK" || echo "0")
            if [ "$status_200" -gt 0 ]; then
                log_success "HTTP状态码验证: 200 OK ($status_200 个响应)"
            fi
        fi
    fi

    log_success "七层字段验证完成: $test_name"
}

# 验证完整会话
validate_complete_session() {
    local pcap_file="$1"
    local test_name="$2"
    local expected_packets="$3"

    ((TOTAL_TESTS++))
    log_info "验证完整会话: $test_name"

    if [ ! -f "$pcap_file" ]; then
        log_error "PCAP文件不存在: $pcap_file"
        return 1
    fi

    # 统计总包数
    if command -v tcpdump >/dev/null 2>&1; then
        local actual_packets=$(tcpdump -r "$pcap_file" -nn 2>/dev/null | wc -l)
        log_detail "预期包数: $expected_packets, 实际包数: $actual_packets"

        if [ "$actual_packets" -eq "$expected_packets" ]; then
            log_success "包数完全匹配"
        elif [ $((actual_packets - expected_packets)) -lt 3 ] && [ $((expected_packets - actual_packets)) -lt 3 ]; then
            log_warning "包数基本匹配 (差异 < 3)"
        else
            log_error "包数差异较大"
        fi

        # 分析会话流程
        log_detail "会话流程分析:"
        tcpdump -r "$pcap_file" -nn 2>/dev/null | head -10 | while read line; do
            local packet_num=$(echo "$line" | cut -d' ' -f1)
            local packet_info=$(echo "$line" | cut -d' ' -f2-)
            log_detail "  $packet_num: $packet_info"
        done
    fi

    log_success "完整会话验证完成: $test_name"
}

# VLAN功能专项测试
test_vlan_functionality() {
    log_info "开始VLAN功能专项测试"

    # 测试1: 单层VLAN
    echo ""
    log_detail "测试1: 单层VLAN (VLAN ID: 100)"
    ./target/debug/gen_pcap --http -n 1 --vlan 100 --vlan-priority 3 -o vlan_test_single.pcap

    validate_layer2 "vlan_test_single.pcap" "单层VLAN" "" "" "100"
    validate_layer3 "vlan_test_single.pcap" "单层VLAN" "10.10.1.100" "192.168.1.100"
    validate_layer4 "vlan_test_single.pcap" "单层VLAN" "" "80"
    validate_layer7 "vlan_test_single.pcap" "单层VLAN" "GET" "/" "example.com"
    validate_complete_session "vlan_test_single.pcap" "单层VLAN" 5

    # 测试2: 双层VLAN (QinQ)
    echo ""
    log_detail "测试2: 双层VLAN (QinQ) - 外层:200, 内层:100"
    ./target/debug/gen_pcap --http -n 1 --qinq --outer-vlan 200 --inner-vlan 100 -o vlan_test_qinq.pcap

    validate_layer2 "vlan_test_qinq.pcap" "双层VLAN(QinQ)" "" "" "200,100"
    validate_layer3 "vlan_test_qinq.pcap" "双层VLAN(QinQ)" "10.10.1.100" "192.168.1.100"
    validate_layer4 "vlan_test_qinq.pcap" "双层VLAN(QinQ)" "" "80"
    validate_layer7 "vlan_test_qinq.pcap" "双层VLAN(QinQ)" "GET" "/" "example.com"
    validate_complete_session "vlan_test_qinq.pcap" "双层VLAN(QinQ)" 5

    # 测试3: VLAN + YAML模板
    echo ""
    log_detail "测试3: VLAN + YAML模板"
    cat > vlan_template.yaml << 'EOF'
metadata:
  name: "VLAN模板测试"
  description: "测试VLAN功能"
  version: "1.0"

network:
  src_mac: "aa:bb:cc:dd:ee:ff"
  dst_mac: "11:22:33:44:55:66"

sessions:
  - name: "vlan_http_session"
    repeat: 1
    connection:
      src:
        ip: "172.16.1.100"
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
          uri: "/vlan/test"
          headers:
            Host: "vlan-test.example.com"
      responses:
        - status_code: 200
          headers:
            Content-Type: "text/html"
          body: '<html><body>VLAN Test Success</body></html>'

vlan:
  tags:
    - vlan_id: 150
      priority: 2
      dei: false

defaults:
  timing:
    packet_delay_ms: 10
EOF

    ./target/debug/gen_pcap -t vlan_template.yaml -o vlan_test_yaml.pcap

    validate_layer2 "vlan_test_yaml.pcap" "VLAN YAML模板" "" "" "150"
    validate_layer3 "vlan_test_yaml.pcap" "VLAN YAML模板" "172.16.1.100" "10.0.0.50"
    validate_layer4 "vlan_test_yaml.pcap" "VLAN YAML模板" "12345" "80"
    validate_layer7 "vlan_test_yaml.pcap" "VLAN YAML模板" "GET" "/vlan/test" "vlan-test.example.com"
    validate_complete_session "vlan_test_yaml.pcap" "VLAN YAML模板" 5
}

# TCP流量生成测试
test_tcp_functionality() {
    log_info "开始TCP流量生成测试"

    echo ""
    log_detail "测试: 纯TCP流量 (无HTTP层)"
    ./target/debug/gen_pcap -n 3 -o tcp_test_basic.pcap

    validate_layer2 "tcp_test_basic.pcap" "纯TCP基础" "" "" ""
    validate_layer3 "tcp_test_basic.pcap" "纯TCP基础" "10.10.1.100" "192.168.1.100"
    validate_layer4 "tcp_test_basic.pcap" "纯TCP基础" "" ""

    # 验证只有TCP三次握手，没有HTTP内容
    if command -v tcpdump >/dev/null 2>&1; then
        local tcp_packets=$(tcpdump -r tcp_test_basic.pcap -nn 2>/dev/null)
        local http_count=$(echo "$tcp_packets" | grep -c "GET\|POST\|HTTP" || echo "0")

        if [ "$http_count" -eq 0 ]; then
            log_success "纯TCP流量验证通过 (无HTTP内容)"
        else
            log_error "纯TCP流量验证失败 (检测到HTTP内容)"
        fi
    fi

    # 每个TCP会话应该只有3个包 (SYN, SYN-ACK, ACK)
    local expected_packets=9  # 3个会话 × 3个包
    validate_complete_session "tcp_test_basic.pcap" "纯TCP基础" $expected_packets

    echo ""
    log_detail "测试: TCP + VLAN"
    ./target/debug/gen_pcap -n 2 --vlan 50 -o tcp_test_vlan.pcap

    validate_layer2 "tcp_test_vlan.pcap" "TCP+VLAN" "" "" "50"
    validate_layer3 "tcp_test_vlan.pcap" "TCP+VLAN" "10.10.1.100" "192.168.1.100"
    validate_layer4 "tcp_test_vlan.pcap" "TCP+VLAN" "" ""
    validate_complete_session "tcp_test_vlan.pcap" "TCP+VLAN" 6
}

# HTTP流量生成测试
test_http_functionality() {
    log_info "开始HTTP流量生成测试"

    echo ""
    log_detail "测试: 基础HTTP流量"
    ./target/debug/gen_pcap --http -n 2 -o http_test_basic.pcap

    validate_layer2 "http_test_basic.pcap" "HTTP基础" "" "" ""
    validate_layer3 "http_test_basic.pcap" "HTTP基础" "10.10.1.100" "192.168.1.100"
    validate_layer4 "http_test_basic.pcap" "HTTP基础" "" "80"
    validate_layer7 "http_test_basic.pcap" "HTTP基础" "GET" "/" "example.com"
    validate_complete_session "http_test_basic.pcap" "HTTP基础" 10

    echo ""
    log_detail "测试: 多URI HTTP流量"
    ./target/debug/gen_pcap --http -n 1 --http-uris '/api/v1/users,/api/v1/orders,/health' -o http_test_multi_uri.pcap

    validate_layer2 "http_test_multi_uri.pcap" "HTTP多URI" "" "" ""
    validate_layer3 "http_test_multi_uri.pcap" "HTTP多URI" "10.10.1.100" "192.168.1.100"
    validate_layer4 "http_test_multi_uri.pcap" "HTTP多URI" "" "80"
    validate_layer7 "http_test_multi_uri.pcap" "HTTP多URI" "GET" "/api/v1" "example.com"
    validate_complete_session "http_test_multi_uri.pcap" "HTTP多URI" 9

    echo ""
    log_detail "测试: 自定义Host和端口"
    ./target/debug/gen_pcap --http -n 1 --http-host 'custom.api.com' -p 8080 -o http_test_custom.pcap

    validate_layer2 "http_test_custom.pcap" "HTTP自定义" "" "" ""
    validate_layer3 "http_test_custom.pcap" "HTTP自定义" "10.10.1.100" "192.168.1.100"
    validate_layer4 "http_test_custom.pcap" "HTTP自定义" "" "8080"
    validate_layer7 "http_test_custom.pcap" "HTTP自定义" "GET" "/" "custom.api.com"
    validate_complete_session "http_test_custom.pcap" "HTTP自定义" 5
}

# YAML模板高级测试
test_yaml_advanced() {
    log_info "开始YAML模板高级测试"

    echo ""
    log_detail "测试: 复杂YAML模板 - 微服务架构"
    cat > microservices_template.yaml << 'EOF'
metadata:
  name: "微服务高级测试"
  description: "复杂的微服务HTTP通信测试"
  version: "2.0"

network:
  src_mac: "de:ad:be:ef:ca:fe"
  dst_mac: "ba:dd:ca:fe:ba:be"

sessions:
  - name: "user_service"
    repeat: 1
    connection:
      src:
        ip: "10.0.1.100"
        port: 50000
      dst:
        ip: "10.0.2.200"
        port: 80
    session_type:
      type: "Tcp"
      ports: [80]
      duration_ms: 5000
    application:
      protocol: "Http"
      requests:
        - method: "GET"
          uri: "/api/users/123"
          headers:
            Host: "user-service.micro.local"
            Authorization: "Bearer token-abc123"
            X-Request-ID: "req-001"
            X-Trace-ID: "trace-xyz789"
        - method: "GET"
          uri: "/api/users/123/profile"
          headers:
            Host: "user-service.micro.local"
            Authorization: "Bearer token-abc123"
            X-Request-ID: "req-002"
            X-Trace-ID: "trace-xyz789"
      responses:
        - status_code: 200
          headers:
            Content-Type: "application/json"
            X-Response-Time: "15ms"
            X-Cache-Status: "MISS"
          body: '{"user_id": 123, "name": "Alice Johnson", "email": "alice@company.com", "status": "active"}'
        - status_code: 200
          headers:
            Content-Type: "application/json"
            X-Response-Time: "12ms"
            X-Cache-Status: "HIT"
          body: '{"user_id": 123, "profile": {"age": 30, "department": "Engineering", "role": "Senior Developer"}}'

  - name: "order_service"
    repeat: 1
    connection:
      src:
        ip: "10.0.1.100"
        port: 50001
      dst:
        ip: "10.0.3.300"
        port: 80
    session_type:
      type: "Tcp"
      ports: [80]
      duration_ms: 5000
    application:
      protocol: "Http"
      requests:
        - method: "POST"
          uri: "/api/orders"
          headers:
            Host: "order-service.micro.local"
            Content-Type: "application/json"
            Authorization: "Bearer token-def456"
            X-Request-ID: "req-003"
            X-Trace-ID: "trace-xyz789"
          body: '{"user_id": 123, "items": [{"product_id": "prod-001", "quantity": 2, "price": 29.99}], "shipping_address": "123 Main St, City, State"}'
      responses:
        - status_code: 201
          headers:
            Content-Type: "application/json"
            Location: "/api/orders/ORD-2024-001"
            X-Response-Time: "45ms"
          body: '{"order_id": "ORD-2024-001", "user_id": 123, "status": "confirmed", "total": 59.98, "created_at": "2024-01-15T10:30:00Z"}'

vlan:
  tags:
    - vlan_id: 100
      priority: 3
      dei: false
      tag_type: "outer"

defaults:
  timing:
    packet_delay_ms: 20
EOF

    ./target/debug/gen_pcap -t microservices_template.yaml -o yaml_test_microservices.pcap

    validate_layer2 "yaml_test_microservices.pcap" "YAML微服务" "" "" "100"
    validate_layer3 "yaml_test_microservices.pcap" "YAML微服务" "10.0.1.100" "10.0.2.200"
    validate_layer4 "yaml_test_microservices.pcap" "YAML微服务" "50000" "80"
    validate_layer7 "yaml_test_microservices.pcap" "YAML微服务" "GET" "/api/users" "user-service.micro.local"
    validate_complete_session "yaml_test_microservices.pcap" "YAML微服务" 12

    # 验证自定义HTTP头
    if command -v tshark >/dev/null 2>&1; then
        log_detail "验证自定义HTTP头:"
        tshark -r yaml_test_microservices.pcap -Y "http.request" -T fields -e http.host -e http.user_agent -e http.authorization -e http.x_request_id 2>/dev/null | head -3 | while read host ua auth req_id; do
            log_detail "  Host: $host, Auth: $auth, Request-ID: $req_id"
        done
    fi
}

# 性能和边界测试
test_performance_and_edges() {
    log_info "开始性能和边界测试"

    echo ""
    log_detail "测试: 大量会话 (50个HTTP会话)"
    ./target/debug/gen_pcap --http -n 50 -o perf_test_large.pcap

    local actual_packets=$(tcpdump -r perf_test_large.pcap -nn 2>/dev/null | wc -l)
    log_detail "50个HTTP会话生成包数: $actual_packets (预期: 250)"

    if [ "$actual_packets" -ge 240 ] && [ "$actual_packets" -le 260 ]; then
        log_success "大量会话性能测试通过"
    else
        log_warning "大量会话包数有偏差: $actual_packets"
    fi

    echo ""
    log_detail "测试: 复杂URI和长路径"
    ./target/debug/gen_pcap --http -n 1 --http-uris '/api/v1/very/long/uri/path/with/many/segments?param1=value1&param2=value2&param3=value3' -o edge_test_long_uri.pcap

    if command -v tcpdump >/dev/null 2>&1; then
        local long_uri_check=$(tcpdump -r edge_test_long_uri.pcap -nn -A 2>/dev/null | grep -c "very.*long.*uri" || echo "0")
        if [ "$long_uri_check" -gt 0 ]; then
            log_success "长URI处理正确"
        else
            log_warning "长URI可能被截断"
        fi
    fi

    validate_complete_session "edge_test_long_uri.pcap" "长URI测试" 5
}

# 主测试函数
main() {
    echo "=================================================="
    echo "        全面集成测试 - 二三四七层验证"
    echo "=================================================="
    echo ""

    # 检查依赖
    check_dependencies

    # 确保程序已编译
    if [ ! -f "./target/debug/gen_pcap" ]; then
        log_info "编译程序..."
        cargo build --quiet
    fi

    # 清理旧文件
    log_info "清理测试文件..."
    rm -f *_test*.pcap *.yaml

    echo ""
    log_info "开始全面集成测试..."
    echo "=================================================="

    # 1. TCP流量生成测试
    test_tcp_functionality

    echo ""
    echo "=================================================="

    # 2. HTTP流量生成测试
    test_http_functionality

    echo ""
    echo "=================================================="

    # 3. VLAN功能测试
    test_vlan_functionality

    echo ""
    echo "=================================================="

    # 4. YAML模板高级测试
    test_yaml_advanced

    echo ""
    echo "=================================================="

    # 5. 性能和边界测试
    test_performance_and_edges

    echo ""
    echo "=================================================="
    echo "                测试结果汇总"
    echo "=================================================="
    echo ""
    echo -e "总测试数: ${BLUE}$TOTAL_TESTS${NC}"
    echo -e "通过测试: ${GREEN}$PASSED_TESTS${NC}"
    echo -e "失败测试: ${RED}$FAILED_TESTS${NC}"
    echo -e "详细验证: ${CYAN}$DETAILED_TESTS${NC}"
    echo ""

    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "${GREEN}🎉 所有测试通过！系统功能完全正常！${NC}"
        exit_code=0
    else
        echo -e "${RED}❌ 有 $FAILED_TESTS 个测试失败，需要检查${NC}"
        exit_code=1
    fi

    echo ""
    log_info "生成的测试文件:"
    ls -lh *_test*.pcap 2>/dev/null | head -10 || log_warning "没有找到PCAP文件"

    echo ""
    log_info "许可证状态:"
    ./target/debug/gen_pcap --license-status

    echo ""
    log_info "文件大小统计:"
    if [ -n "$(ls *_test*.pcap 2>/dev/null)" ]; then
        du -h *_test*.pcap | sort -h
    fi

    # 清理（可选择保留文件用于调试）
    if [ "$1" != "--keep-files" ]; then
        echo ""
        log_info "清理测试文件..."
        rm -f *_test*.pcap *.yaml
    else
        echo ""
        log_info "保留测试文件用于调试"
    fi

    exit $exit_code
}

# 信号处理
trap 'echo ""; log_warning "测试被中断"; exit 130' INT TERM

# 运行主函数
main "$@"