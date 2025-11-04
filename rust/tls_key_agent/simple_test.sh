#!/bin/bash

echo "=== TLS Key Agent 简单测试脚本 ==="
echo "测试时间: $(date)"
echo

# 设置环境变量
export RUST_LOG=debug
export LD_PRELOAD="/root/workspace/code_repo/rust/tls_key_agent/target/release/build/tls_key_agent-14464a6856f749c9/out/libopenssl_hook.so"

# 创建密钥日志文件路径
KEYLOG_FILE="/tmp/simple_tls_test_$(date +%s).log"

echo "1. 检查动态库文件..."
if [ -f "$LD_PRELOAD" ]; then
    echo "✓ 动态库文件存在: $LD_PRELOAD"
    ls -la "$LD_PRELOAD"
else
    echo "✗ 动态库文件不存在: $LD_PRELOAD"
    exit 1
fi

echo
echo "2. 检查OpenSSL版本..."
openssl version

echo
echo "3. 创建测试配置..."
cat > /tmp/test_config.toml << 'EOF'
[agent]
name = "TLS Key Agent Test"
description = "Simple test configuration"

[extraction]
enable_client_random = true
enable_master_secret = true
enable_session_tickets = false

[transport]
enabled_transports = ["File"]

[transport.tcp]
enabled = false

[transport.file]
enabled = true
output_path = "/tmp/simple_tls_test.log"
rotation = false
max_file_size = 1048576
max_files = 10

[[filters]]
name = "All HTTPS Traffic"
enabled = true

[filters.five_tuple]
dst_port = 443
protocol = "TCP"

[filters.process_name]
# 可选：限制特定进程
EOF

echo "✓ 配置文件创建完成"

echo
echo "4. 执行HTTPS请求测试..."
echo "目标: https://www.baidu.com"
echo "密钥日志文件: $KEYLOG_FILE"

# 使用curl进行HTTPS请求
echo "正在执行HTTPS请求..."
curl -v --connect-timeout 10 --max-time 15 https://www.baidu.com > /dev/null 2>&1

CURL_EXIT_CODE=$?
echo "curl 退出码: $CURL_EXIT_CODE"

echo
echo "5. 检查密钥日志文件..."
if [ -f "$KEYLOG_FILE" ]; then
    echo "✓ 密钥日志文件已创建"
    echo "文件大小: $(wc -c < "$KEYLOG_FILE") 字节"
    echo "文件内容:"
    cat "$KEYLOG_FILE"

    # 检查是否有密钥内容
    if grep -q "CLIENT_RANDOM" "$KEYLOG_FILE"; then
        echo "✓ 检测到 CLIENT_RANDOM 条目"
        echo "密钥数量: $(grep -c "CLIENT_RANDOM" "$KEYLOG_FILE")"
    else
        echo "⚠ 未检测到 CLIENT_RANDOM 条目"
    fi

    if grep -q "RSA\|ECDHE" "$KEYLOG_FILE"; then
        echo "✓ 检测到其他密钥类型"
    else
        echo "⚠ 未检测到其他密钥类型"
    fi
else
    echo "✗ 密钥日志文件未创建"
fi

echo
echo "6. 清理..."
# 不删除日志文件以便检查
echo "日志文件保留在: $KEYLOG_FILE"

echo
echo "=== 测试完成 ==="