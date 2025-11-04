#!/bin/bash

echo "=== Master Secret 提取测试 ==="
echo "测试时间: $(date)"
echo

# 清理之前的日志文件
rm -f /tmp/openssl_keylog.txt /tmp/test_tls_*.log

# 设置环境变量
export RUST_LOG=debug
export LD_PRELOAD="/root/workspace/code_repo/rust/tls_key_agent/target/release/build/tls_key_agent-14464a6856f749c9/out/libopenssl_hook.so"

echo "1. 测试环境设置..."
if [ -f "$LD_PRELOAD" ]; then
    echo "✓ Hook库已加载: $LD_PRELOAD"
else
    echo "✗ Hook库不存在"
    exit 1
fi

echo
echo "2. 执行HTTPS请求测试..."
echo "目标: https://www.baidu.com"

# 执行curl请求
echo "正在发送HTTPS请求..."
curl -v --connect-timeout 10 --max-time 15 https://www.baidu.com > /dev/null 2>&1

CURL_EXIT_CODE=$?
echo "curl 退出码: $CURL_EXIT_CODE"

echo
echo "3. 检查密钥日志文件..."

# 检查OpenSSL keylog文件
if [ -f "/tmp/openssl_keylog.txt" ]; then
    echo "✓ OpenSSL Keylog文件已创建"
    echo "文件内容:"
    cat /tmp/openssl_keylog.txt

    echo
    echo "密钥分析:"
    if grep -q "CLIENT_RANDOM" /tmp/openssl_keylog.txt; then
        echo "✓ 检测到 CLIENT_RANDOM 条目"
        echo "  数量: $(grep -c "CLIENT_RANDOM" /tmp/openssl_keylog.txt)"

        # 提取并显示Client Random
        echo "  Client Random 值:"
        grep "CLIENT_RANDOM" /tmp/openssl_keylog.txt | head -3
    fi

    if grep -q "MASTER_SECRET" /tmp/openssl_keylog.txt; then
        echo "✓ 检测到 MASTER_SECRET 条目"
        echo "  数量: $(grep -c "MASTER_SECRET" /tmp/openssl_keylog.txt)"

        # 提取并显示Master Secret
        echo "  Master Secret 值:"
        grep "MASTER_SECRET" /tmp/openssl_keylog.txt | head -3
    else
        echo "⚠ 未检测到 MASTER_SECRET 条目"
    fi

    if grep -q "TRAFFIC_SECRET" /tmp/openssl_keylog.txt; then
        echo "✓ 检测到 TLS 1.3 流量密钥"
        echo "  数量: $(grep -c "TRAFFIC_SECRET" /tmp/openssl_keylog.txt)"
    fi
else
    echo "⚠ OpenSSL Keylog文件未创建"
fi

echo
echo "4. 检查其他密钥文件..."
for file in /tmp/test_tls_*.log; do
    if [ -f "$file" ]; then
        echo "发现密钥文件: $file"
        echo "内容:"
        cat "$file"
        echo
    fi
done

echo
echo "5. 验证密钥完整性..."

# 检查是否有完整的密钥对
if [ -f "/tmp/openssl_keylog.txt" ]; then
    client_random_count=$(grep -c "CLIENT_RANDOM" /tmp/openssl_keylog.txt || echo "0")

    if [ "$client_random_count" -gt 0 ]; then
        echo "✓ 获取到 $client_random_count 个 Client Random"

        # 检查是否也有Master Secret
        if grep -q "MASTER_SECRET\|TRAFFIC_SECRET" /tmp/openssl_keylog.txt; then
            echo "✓ 获取到解密所需的密钥材料"
            echo "  结论: 可能可以进行TLS流量解密"
        else
            echo "⚠ 只有 Client Random，缺少 Master Secret"
            echo "  结论: 无法解密TLS流量"
        fi
    else
        echo "⚠ 未获取到任何密钥信息"
    fi
else
    echo "⚠ 没有任何密钥日志"
fi

echo
echo "=== 测试完成 ==="