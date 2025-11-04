#!/bin/bash

echo "=== 使用环境变量测试 TLS 密钥获取 ==="
echo "测试时间: $(date)"
echo

# 清理之前的日志文件
rm -f /tmp/test_keylog.txt /tmp/test_traffic.pcap

echo "1. 设置环境变量..."
export SSLKEYLOGFILE="/tmp/test_keylog.txt"
export RUST_LOG=info

echo "✓ SSLKEYLOGFILE 设置为: $SSLKEYLOGFILE"

echo
echo "2. 执行HTTPS请求测试..."
echo "目标: https://www.baidu.com"

# 执行curl请求
echo "正在发送HTTPS请求..."
curl -v --connect-timeout 10 --max-time 15 https://www.baidu.com > /dev/null 2>&1

CURL_EXIT_CODE=$?
echo "curl 退出码: $CURL_EXIT_CODE"

echo
echo "3. 检查生成的密钥日志文件..."

if [ -f "$SSLKEYLOGFILE" ]; then
    echo "✓ 密钥日志文件已创建: $SSLKEYLOGFILE"
    echo "文件大小: $(wc -c < "$SSLKEYLOGFILE") 字节"
    echo "文件内容:"
    cat "$SSLKEYLOGFILE"
    echo

    echo "4. 分析密钥内容..."

    # 分析密钥类型
    client_random_count=$(grep -c "CLIENT_RANDOM" "$SSLKEYLOGFILE" 2>/dev/null || echo "0")
    master_secret_count=$(grep -c "MASTER_SECRET" "$SSLKEYLOGFILE" 2>/dev/null || echo "0")
    traffic_secret_count=$(grep -c "TRAFFIC_SECRET" "$SSLKEYLOGFILE" 2>/dev/null || echo "0")

    echo "密钥统计:"
    echo "  - Client Random: $client_random_count"
    echo "  - Master Secret: $master_secret_count"
    echo "  - Traffic Secret: $traffic_secret_count"

    if [ "$client_random_count" -gt 0 ]; then
        echo "✓ 成功获取 Client Random"

        # 显示 Client Random 值
        echo "  Client Random 值:"
        grep "CLIENT_RANDOM" "$SSLKEYLOGFILE" | while read line; do
            parts=($line)
            if [ ${#parts[@]} -ge 3 ]; then
                echo "    ${parts[0]}: ${parts[1]:0:16}..."
                echo "    Secret: ${parts[2]:0:16}..."
            fi
        done
    fi

    if [ "$master_secret_count" -gt 0 ]; then
        echo "✓ 成功获取 Master Secret"
        echo "  这意味着可以进行TLS流量解密!"
    fi

    if [ "$traffic_secret_count" -gt 0 ]; then
        echo "✓ 成功获取 TLS 1.3 流量密钥"
        echo "  这意味着可以进行TLS 1.3流量解密!"
    fi

    echo
    echo "5. 解密能力评估..."
    if [ "$client_random_count" -gt 0 ] && [ "$master_secret_count" -gt 0 ]; then
        echo "✅ 具备 TLS 1.2 解密能力"
        echo "   - Client Random: $client_random_count 个"
        echo "   - Master Secret: $master_secret_count 个"
        echo "   - 可以生成完整的密钥材料"
    elif [ "$traffic_secret_count" -gt 0 ]; then
        echo "✅ 具备 TLS 1.3 解密能力"
        echo "   - Traffic Secret: $traffic_secret_count 个"
        echo "   - 可以直接解密流量"
    elif [ "$client_random_count" -gt 0 ]; then
        echo "⚠️  具备部分密钥获取能力"
        echo "   - Client Random: $client_random_count 个"
        echo "   - 缺少 Master Secret 或 Traffic Secret"
        echo "   - 无法解密TLS流量"
    else
        echo "❌ 未获取到任何密钥信息"
        echo "   - 可能是环境不支持或配置问题"
    fi

else
    echo "❌ 密钥日志文件未创建"
    echo "可能的原因:"
    echo "  - OpenSSL版本不支持 SSLKEYLOGFILE"
    echo "  - 环境变量设置无效"
    echo "  - curl 使用了不同的TLS库"
fi

echo
echo "6. 验证OpenSSL版本..."
openssl_version=$(openssl version 2>/dev/null)
echo "当前OpenSSL版本: $openssl_version"

echo
echo "=== 测试完成 ==="