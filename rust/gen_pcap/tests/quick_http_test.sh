#!/bin/bash

# 快速HTTP流量测试脚本
# 验证TCP三次握手修复后的基础功能

echo "=========================================="
echo "       HTTP流量快速测试"
echo "=========================================="

# 确保程序已编译
if [ ! -f "./target/debug/gen_pcap" ]; then
    echo "编译程序..."
    cargo build --quiet
fi

# 测试1: 基础HTTP流量 (3个会话)
echo ""
echo "测试1: 基础HTTP流量"
./target/debug/gen_pcap --http -n 3 -o quick_test_basic.pcap
echo "预期: 3个会话 × (3个握手包 + 2个HTTP包) = 15个包"
if command -v tcpdump >/dev/null 2>&1; then
    actual_count=$(tcpdump -r quick_test_basic.pcap -nn 2>/dev/null | wc -l)
    echo "实际: $actual_count 个包"
    if [ "$actual_count" -eq 15 ]; then
        echo "✅ 测试1通过"
    else
        echo "❌ 测试1失败"
    fi
fi

# 测试2: 多URI HTTP流量 (1个会话，3个URI)
echo ""
echo "测试2: 多URI HTTP流量"
./target/debug/gen_pcap --http -n 1 --http-uris '/api,/test,/health' -o quick_test_multi_uri.pcap
echo "预期: 1个会话 × (3个握手包 + 3×2个HTTP包) = 9个包"
if command -v tcpdump >/dev/null 2>&1; then
    actual_count=$(tcpdump -r quick_test_multi_uri.pcap -nn 2>/dev/null | wc -l)
    echo "实际: $actual_count 个包"
    if [ "$actual_count" -eq 9 ]; then
        echo "✅ 测试2通过"
    else
        echo "❌ 测试2失败"
    fi
fi

# 测试3: 验证TCP三次握手存在
echo ""
echo "测试3: 验证TCP三次握手"
if command -v tcpdump >/dev/null 2>&1; then
    echo "检查前3个包是否为TCP三次握手:"
    tcpdump -r quick_test_basic.pcap -nn -c 3 2>/dev/null | while read line; do
        echo "  $line"
    done

    # 检查是否包含SYN, SYN-ACK, ACK
    syn_count=$(tcpdump -r quick_test_basic.pcap -nn -c 3 2>/dev/null | grep -c "Flags \[S\]" || echo "0")
    syn_ack_count=$(tcpdump -r quick_test_basic.pcap -nn -c 3 2>/dev/null | grep -c "Flags \[S.\]" || echo "0")
    ack_count=$(tcpdump -r quick_test_basic.pcap -nn -c 3 2>/dev/null | grep -c "Flags \[.\]" | head -1 || echo "0")

    if [ "$syn_count" -eq 1 ] && [ "$syn_ack_count" -eq 1 ] && [ "$ack_count" -eq 1 ]; then
        echo "✅ 测试3通过 - TCP三次握手正确"
    else
        echo "❌ 测试3失败 - TCP三次握手不完整"
    fi
fi

# 测试4: 验证HTTP内容
echo ""
echo "测试4: 验证HTTP内容"
if command -v tcpdump >/dev/null 2>&1; then
    echo "检查HTTP请求和响应:"
    tcpdump -r quick_test_basic.pcap -nn -A 2>/dev/null | grep -E "(GET / HTTP|HTTP/1.1 200)" | head -2
    http_count=$(tcpdump -r quick_test_basic.pcap -nn -A 2>/dev/null | grep -c "GET / HTTP" || echo "0")
    response_count=$(tcpdump -r quick_test_basic.pcap -nn -A 2>/dev/null | grep -c "HTTP/1.1 200" || echo "0")

    if [ "$http_count" -eq 3 ] && [ "$response_count" -eq 3 ]; then
        echo "✅ 测试4通过 - HTTP请求和响应正确"
    else
        echo "❌ 测试4失败 - HTTP内容不完整 (请求: $http_count, 响应: $response_count)"
    fi
fi

# 清理
rm -f quick_test_*.pcap

echo ""
echo "=========================================="
echo "           快速测试完成"
echo "=========================================="
echo ""
echo "如需运行完整集成测试，请执行:"
echo "  ./tests/http_integration_test.sh"
echo ""
echo "许可证状态:"
./target/debug/gen_pcap --license-status