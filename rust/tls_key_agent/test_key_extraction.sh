#!/bin/bash

# 密钥提取功能测试脚本

set -e

echo "=========================================="
echo "TLS Key Agent 密钥提取功能测试"
echo "=========================================="

# 编译Hook库
echo "1. 编译Hook库..."
if ! cargo build --release --lib; then
    echo "❌ 编译失败"
    exit 1
fi
echo "✅ Hook库编译成功"

# 编译主程序
echo "2. 编译主程序..."
if ! cargo build --release; then
    echo "❌ 主程序编译失败"
    exit 1
fi
echo "✅ 主程序编译成功"

# 检查Hook库导出符号
echo "3. 检查Hook库符号..."
if command -v nm &> /dev/null; then
    echo "Hook库导出的TLS相关符号:"
    nm target/release/libtls_key_agent.so | grep -E "(SSL_|TLS)" || echo "   (未找到TLS符号)"
    echo
fi

# 检查OpenSSL库可用性
echo "4. 检查OpenSSL环境..."
echo "OpenSSL版本: $(openssl version)"
echo "OpenSSL库位置:"
ldconfig -p | grep libssl || echo "   未找到libssl库"

# 创建测试环境
echo "5. 创建测试环境..."
TEST_DIR="/tmp/tls_test_$$"
mkdir -p "$TEST_DIR"
export SSLKEYLOGFILE="$TEST_DIR/test_keys.log"
echo "   密钥日志文件: $SSLKEYLOGFILE"

# 测试简单HTTPS连接
echo "6. 测试HTTPS连接密钥提取..."
echo "   测试连接到 https://httpbin.org/get"

# 使用curl进行测试（会触发TLS握手）
if command -v curl &> /dev/null; then
    echo "   使用curl测试..."
    LD_PRELOAD="$(pwd)/target/release/libtls_key_agent.so" curl -s -o /dev/null \
        -w "HTTP状态码: %{http_code}\n" \
        --connect-timeout 10 \
        --max-time 15 \
        https://httpbin.org/get || echo "   ⚠️  curl测试失败（网络问题或密钥提取问题）"
else
    echo "   ⚠️  curl不可用，跳过网络测试"
fi

# 检查密钥日志
echo "7. 检查密钥提取结果..."
if [[ -f "$SSLKEYLOGFILE" ]]; then
    echo "   ✅ 密钥日志文件已创建"
    echo "   文件大小: $(wc -c < "$SSLKEYLOGFILE") 字节"
    echo "   内容预览:"
    head -3 "$SSLKEYLOGFILE" 2>/dev/null | sed 's/^/      /' || echo "      (无法读取文件内容)"

    if grep -q "CLIENT_RANDOM" "$SSLKEYLOGFILE" 2>/dev/null; then
        echo "   ✅ 成功提取到Client Random"
    else
        echo "   ⚠️  未找到Client Random"
    fi

    if grep -q "MASTER_SECRET" "$SSLKEYLOGFILE" 2>/dev/null; then
        echo "   ✅ 成功提取到Master Secret"
    else
        echo "   ⚠️  未找到Master Secret（这在现代OpenSSL中是正常的）"
    fi
else
    echo "   ❌ 密钥日志文件未创建"
fi

# 清理测试环境
echo "8. 清理测试环境..."
rm -rf "$TEST_DIR"
unset SSLKEYLOGFILE

echo "=========================================="
echo "测试完成！"
echo "=========================================="
echo ""
echo "📋 测试结果说明:"
echo "✅ 表示功能正常"
echo "⚠️  表示部分功能可用（现代OpenSSL限制）"
echo "❌ 表示功能异常"
echo ""
echo "💡 在生产环境中，建议:"
echo "1. 使用TLS KeyLog环境变量配合现代OpenSSL"
echo "2. 监控目标应用的TLS库版本"
echo "3. 根据实际网络环境调整测试参数"