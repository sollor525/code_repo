#!/bin/bash

# TLS流量捕获和密钥提取脚本
# 用于验证TLS解密功能

set -e

echo "=========================================="
echo "   TLS 流量捕获和密钥提取验证脚本"
echo "=========================================="
echo "测试时间: $(date)"
echo

# 配置参数
TEST_DIR="/tmp/tls_decrypt_test_$(date +%s)"
KEYLOG_FILE="$TEST_DIR/tls_keys.log"
PCAP_FILE="$TEST_DIR/tls_traffic.pcap"
TARGET_HOST="www.baidu.com"
TARGET_PORT="443"
TEST_URL="https://$TARGET_HOST"

# 创建测试目录
mkdir -p "$TEST_DIR"

# 清理函数
cleanup() {
    echo
    echo "清理资源..."
    pkill -f tcpdump 2>/dev/null || true
    echo "测试文件保存在: $TEST_DIR"
}
trap cleanup EXIT

echo "1. 准备测试环境..."
echo "测试目录: $TEST_DIR"
echo "密钥日志: $KEYLOG_FILE"
echo "流量包: $PCAP_FILE"
echo "目标: $TARGET_URL"
echo

# 检查必要的工具
echo "2. 检查工具可用性..."
missing_tools=()

if ! command -v tcpdump >/dev/null 2>&1; then
    missing_tools+=("tcpdump")
fi

if ! command -v curl >/dev/null 2>&1; then
    missing_tools+=("curl")
fi

if ! command -v openssl >/dev/null 2>&1; then
    missing_tools+=("openssl")
fi

if [ ${#missing_tools[@]} -gt 0 ]; then
    echo "❌ 缺少必要工具: ${missing_tools[*]}"
    echo "请安装后再运行此脚本"
    exit 1
fi

echo "✓ 所有必要工具已安装"
echo

# 设置密钥日志环境变量
echo "3. 配置密钥日志..."
export SSLKEYLOGFILE="$KEYLOG_FILE"
echo "✓ SSLKEYLOGFILE 设置为: $SSLKEYLOGFILE"

# 开始流量捕获
echo "4. 开始捕获TLS流量..."
echo "启动 tcpdump 监听目标流量..."

# 查找网络接口
INTERFACE=$(ip route | grep default | head -1 | awk '{print $5}')
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"  # 默认接口
fi

echo "使用网络接口: $INTERFACE"

# 启动tcpdump（后台运行）
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
    -s 0 \
    "host $TARGET_HOST and port $TARGET_PORT" \
    2>/dev/null &

TCPDUMP_PID=$!
echo "tcpdump PID: $TCPDUMP_PID"

# 等待tcpdump启动
sleep 2

echo "✓ 流量捕获已启动"
echo

# 执行TLS请求
echo "5. 执行TLS连接测试..."
echo "正在连接到 $TARGET_URL ..."

# 执行多次HTTPS请求以确保捕获到完整握手
for i in {1..3}; do
    echo "请求 $i/3..."
    curl -s -o /dev/null \
         --connect-timeout 10 \
         --max-time 15 \
         "$TARGET_URL" || true

    sleep 1
done

echo "✓ TLS请求完成"
echo

# 停止流量捕获
echo "6. 停止流量捕获..."
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true

echo "✓ 流量捕获已停止"
echo

# 分析捕获的结果
echo "7. 分析捕获结果..."

echo "=== 密钥日志分析 ==="
if [ -f "$KEYLOG_FILE" ]; then
    echo "✓ 密钥日志文件已生成"
    echo "文件大小: $(wc -c < "$KEYLOG_FILE") 字节"
    echo "内容:"
    cat "$KEYLOG_FILE"
    echo

    # 解析密钥信息
    client_random_lines=$(grep -c "^CLIENT_RANDOM " "$KEYLOG_FILE" 2>/dev/null || echo "0")

    if [ "$client_random_lines" -gt 0 ]; then
        echo "✓ 检测到 $client_random_lines 个密钥记录"

        echo "密钥详情:"
        grep "^CLIENT_RANDOM " "$KEYLOG_FILE" | while read -r line; do
            # 解析CLIENT_RANDOM行
            parts=($line)
            if [ ${#parts[@]} -ge 3 ]; then
                client_random="${parts[1]}"
                master_secret="${parts[2]}"

                echo "  Client Random: ${client_random:0:16}... (${#client_random} 字节)"
                echo "  Master Secret: ${master_secret:0:16}... (${#master_secret} 字节)"

                # 验证密钥长度
                if [ ${#client_random} -eq 64 ] && [ ${#master_secret} -eq 96 ]; then
                    echo "  ✓ 密钥长度正确 (32+48字节)"
                else
                    echo "  ⚠ 密钥长度异常 (CR:${#client_random}, MS:${#master_secret})"
                fi
                echo
            fi
        done

        # 检查TLS版本
        if grep -q "TRAFFIC_SECRET" "$KEYLOG_FILE"; then
            echo "✓ 检测到 TLS 1.3 流量密钥"
        else
            echo "✓ 检测到 TLS 1.2 密钥格式"
        fi

    else
        echo "⚠ 未检测到密钥记录"
    fi
else
    echo "❌ 密钥日志文件未生成"
fi

echo
echo "=== 流量包分析 ==="
if [ -f "$PCAP_FILE" ]; then
    file_size=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "0")
    echo "✓ 流量包文件已生成"
    echo "文件大小: $file_size 字节"

    if [ "$file_size" -gt 0 ]; then
        packet_count=$(tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | wc -l)
        echo "捕获的包数量: $packet_count"

        echo "流量概览:"
        tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | head -10

        if [ "$packet_count" -gt 5 ]; then
            echo "✓ 捕获了足够的流量进行分析"
        else
            echo "⚠ 捕获的流量较少，可能影响解密测试"
        fi
    else
        echo "⚠ 流量包文件为空"
    fi
else
    echo "❌ 流量包文件未生成"
fi

echo
echo "8. 生成解密配置..."

# 创建Wireshark配置文件
WIRESHARK_PREFS="$TEST_DIR/wireshark_prefs"
cat > "$WIRESHARK_PREFS" << 'EOF'
# Wireshark TLS解密配置
tls.keylog_file: /tmp/tls_decrypt_test_tls_keys.log
EOF

echo "✓ Wireshark配置已创建: $WIRESHARK_PREFS"

# 创建tshark解密命令
TSHARK_DECRYPT_CMD="tshark -r '$PCAP_FILE' -o tls.keylog_file:'$KEYLOG_FILE' -Y 'tls' -V"
echo "tshark解密命令:"
echo "$TSHARK_DECRYPT_CMD"

echo
echo "9. 验证密钥完整性..."

# 密钥验证函数
validate_keys() {
    local keylog_file="$1"

    if [ ! -f "$keylog_file" ]; then
        return 1
    fi

    while IFS= read -r line; do
        if [[ "$line" =~ ^CLIENT_RANDOM\ ([0-9a-f]{64})\ ([0-9a-f]{96})$ ]]; then
            client_random="${BASH_REMATCH[1]}"
            master_secret="${BASH_REMATCH[2]}"

            echo "验证密钥对:"
            echo "  Client Random: $client_random"
            echo "  Master Secret: $master_secret"

            # 检查密钥是否全为零
            if [[ "$master_secret" =~ ^0+$ ]]; then
                echo "  ⚠ Master Secret 全为零，可能无效"
                return 1
            else
                echo "  ✓ Master Secret 包含非零值，可能有效"

                # 计算密钥熵（简单检查）
                non_zero_count=$(echo "$master_secret" | tr -d '0' | wc -c)
                entropy_ratio=$((non_zero_count * 100 / 96))
                echo "  ✓ 密钥熵值: $entropy_ratio%"

                if [ "$entropy_ratio" -gt 30 ]; then
                    echo "  ✓ 密钥质量良好"
                else
                    echo "  ⚠ 密钥质量较低"
                fi
            fi
            return 0
        fi
    done < "$keylog_file"

    return 1
}

if validate_keys "$KEYLOG_FILE"; then
    echo
    echo "🎉 密钥验证成功！"
    echo "✓ Client Random 和 Master Secret 都已正确获取"
    echo "✓ 具备完整的TLS 1.2解密能力"
    echo
    echo "下一步可以使用以下方法进行解密测试:"
    echo "1. 使用Wireshark导入密钥日志文件"
    echo "2. 使用tshark命令行工具"
    echo "3. 使用其他支持SSLKEYLOG的解密工具"
else
    echo
    echo "❌ 密钥验证失败"
    echo "⚠ 可能无法进行完整的TLS解密"
fi

echo
echo "=========================================="
echo "测试完成！"
echo "测试文件保存在: $TEST_DIR"
echo "密钥日志: $KEYLOG_FILE"
echo "流量包: $PCAP_FILE"
echo "=========================================="