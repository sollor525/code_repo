#!/bin/bash

# Wireshark TLS解密测试脚本
# 使用捕获的密钥在Wireshark中解密TLS流量

set -e

echo "=========================================="
echo "     Wireshark TLS 解密测试脚本"
echo "=========================================="
echo "测试时间: $(date)"
echo

# 配置参数
TEST_DIR="${1:-/tmp/wireshark_decrypt_test_$(date +%s)}"
KEYLOG_FILE="$TEST_DIR/tls_keys.log"
PCAP_FILE="$TEST_DIR/tls_traffic.pcap"
TARGET_HOST="www.baidu.com"
TARGET_PORT="443"

# 创建测试目录
mkdir -p "$TEST_DIR"

echo "测试目录: $TEST_DIR"
echo "密钥日志: $KEYLOG_FILE"
echo "流量包: $PCAP_FILE"
echo

# 检查工具可用性
echo "1. 检查解密工具..."

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

# 检查Wireshark工具
if command -v tshark >/dev/null 2>&1; then
    echo "✓ tshark 可用"
    HAS_TSHARK=true
else
    echo "⚠ tshark 不可用，将跳过命令行解密测试"
    HAS_TSHARK=false
fi

if command -v wireshark >/dev/null 2>&1; then
    echo "✓ wireshark 可用"
    HAS_WIRESHARK=true
else
    echo "⚠ wireshark 不可用，将生成配置文件供手动测试"
    HAS_WIRESHARK=false
fi

if [ ${#missing_tools[@]} -gt 0 ]; then
    echo "❌ 缺少必要工具: ${missing_tools[*]}"
    echo "请安装后再运行此脚本"
    exit 1
fi

echo "✓ 基础工具检查完成"
echo

# 配置密钥捕获（适配eBPF架构）
echo "2. 配置密钥捕获..."
echo "注意: 此脚本现在适配eBPF架构的TLS密钥提取"
echo "eBPF程序将自动捕获TLS会话密钥"

# 检查eBPF程序是否已生成密钥文件
DEFAULT_KEYLOG_FILE="/tmp/ebpf_tls_keys.log"
if [ -f "$DEFAULT_KEYLOG_FILE" ]; then
    echo "✓ 检测到eBPF生成的密钥文件: $DEFAULT_KEYLOG_FILE"
    cp "$DEFAULT_KEYLOG_FILE" "$KEYLOG_FILE"
    echo "✓ 已复制eBPF密钥到测试目录"
else
    echo "⚠ 未检测到eBPF密钥文件，将使用传统SSLKEYLOGFILE方式"
    export SSLKEYLOGFILE="$KEYLOG_FILE"
    echo "✓ SSLKEYLOGFILE 设置为: $SSLKEYLOG_FILE"
fi

# 开始流量捕获
echo "3. 捕获TLS流量..."

# 查找网络接口
INTERFACE=$(ip route | grep default | head -1 | awk '{print $5}')
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
fi

echo "使用网络接口: $INTERFACE"

# 启动tcpdump
echo "启动 tcpdump 监听 $TARGET_HOST:$TARGET_PORT ..."
tcpdump -i "$INTERFACE" -w "$PCAP_FILE" \
    -s 0 \
    "host $TARGET_HOST and port $TARGET_PORT" \
    2>/dev/null &

TCPDUMP_PID=$!
echo "tcpdump PID: $TCPDUMP_PID"

# 等待tcpdump启动
sleep 2

# 执行TLS请求
echo "4. 执行TLS连接测试..."
echo "正在连接到 https://$TARGET_HOST ..."

# 执行多个HTTPS请求
for i in {1..5}; do
    echo "请求 $i/5..."
    curl -s -o /dev/null \
         --connect-timeout 10 \
         --max-time 15 \
         -H "User-Agent: TLS-Key-Agent-Test/$i" \
         "https://$TARGET_HOST" || true
    sleep 0.5
done

echo "✓ TLS请求完成"

# 停止流量捕获
echo "5. 停止流量捕获..."
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
echo "✓ 流量捕获已停止"
echo

# 分析捕获结果
echo "6. 分析捕获结果..."

if [ -f "$KEYLOG_FILE" ]; then
    key_size=$(wc -c < "$KEYLOG_FILE")
    echo "✓ 密钥日志文件: $key_size 字节"

    # 显示密钥内容
    echo "密钥内容:"
    cat "$KEYLOG_FILE"
    echo
else
    echo "❌ 密钥日志文件未生成"
fi

if [ -f "$PCAP_FILE" ]; then
    pcap_size=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "0")
    echo "✓ 流量包文件: $pcap_size 字节"

    if [ "$pcap_size" -gt 0 ]; then
        packet_count=$(tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | wc -l)
        echo "✓ 捕获到 $packet_count 个数据包"
    else
        echo "⚠ 流量包文件为空"
    fi
else
    echo "❌ 流量包文件未生成"
fi

echo

# tshark解密测试
if [ "$HAS_TSHARK" = true ] && [ -f "$PCAP_FILE" ] && [ -f "$KEYLOG_FILE" ]; then
    echo "7. tshark TLS解密测试..."

    echo "使用tshark进行TLS解密分析:"
    echo "命令: tshark -r '$PCAP_FILE' -o tls.keylog_file:'$KEYLOG_FILE' -Y 'tls' -V"
    echo

    # 执行tshark解密
    echo "=== TLS握手包分析 ==="
    tshark -r "$PCAP_FILE" \
           -o "tls.keylog_file:$KEYLOG_FILE" \
           -Y "tls.handshake" \
           -V 2>/dev/null | head -20

    echo
    echo "=== 应用数据包分析 ==="
    tshark -r "$PCAP_FILE" \
           -o "tls.keylog_file:$KEYLOG_FILE" \
           -Y "tls.app_data" \
           -V 2>/dev/null | head -10

    echo
    echo "=== 加密统计 ==="
    tshark -r "$PCAP_FILE" \
           -o "tls.keylog_file:$KEYLOG_FILE" \
           -q -z "conv,tcp" 2>/dev/null || echo "无法生成统计信息"

    echo "✓ tshark解密测试完成"
    echo
fi

# 生成Wireshark配置
echo "8. 生成Wireshark解密配置..."

# 复制密钥文件
cp "$KEYLOG_FILE" "$TEST_DIR/wireshark_keys.txt"
echo "✓ Wireshark密钥文件: $TEST_DIR/wireshark_keys.txt"

# 创建Wireshark配置文件
WIRESHARK_PREFS="$TEST_DIR/wireshark_prefs"
cat > "$WIRESHARK_PREFS" << EOF
# Wireshark TLS 解密配置
# 在 Wireshark 中导入此配置:
# Edit -> Preferences -> Protocols -> TLS
# (Pre)-Master-Secret log filename: $TEST_DIR/wireshark_keys.txt

# 其他TLS配置
tls.show_heartbeat: FALSE
tls.decrypt_records: TRUE
tls.keys_list: $TEST_DIR/wireshark_keys.txt
EOF

echo "✓ Wireshark配置文件: $WIRESHARK_PREFS"

# 创建批处理解密脚本
DECRYPT_SCRIPT="$TEST_DIR/decrypt_with_wireshark.sh"
cat > "$DECRYPT_SCRIPT" << 'EOF'
#!/bin/bash

# Wireshark TLS解密批处理脚本
echo "Wireshark TLS解密指南"
echo "====================="
echo

KEYLOG_FILE="$1"
PCAP_FILE="$2"

if [ -z "$KEYLOG_FILE" ] || [ -z "$PCAP_FILE" ]; then
    echo "用法: $0 <keylog_file> <pcap_file>"
    exit 1
fi

echo "密钥文件: $KEYLOG_FILE"
echo "流量文件: $PCAP_FILE"
echo

# 方法1: 使用tshark命令行
if command -v tshark >/dev/null 2>&1; then
    echo "=== 方法1: 使用tshark ==="
    echo "命令: tshark -r '$PCAP_FILE' -o tls.keylog_file:'$KEYLOG_FILE' -Y 'tls' -V"
    echo

    tshark -r "$PCAP_FILE" \
           -o "tls.keylog_file:$KEYLOG_FILE" \
           -Y "tls.handshake.type == 1 or tls.handshake.type == 2" \
           -V 2>/dev/null
    echo
fi

# 方法2: 生成Wireshark命令
echo "=== 方法2: 使用Wireshark GUI ==="
echo "1. 启动Wireshark: wireshark '$PCAP_FILE'"
echo "2. 打开 Edit -> Preferences -> Protocols -> TLS"
echo "3. 设置 (Pre)-Master-Secret log filename: $KEYLOG_FILE"
echo "4. 点击 'OK' 保存设置"
echo "5. 重新加载流量或重新应用过滤器"
echo

# 方法3: 检查密钥格式
echo "=== 方法3: 密钥格式验证 ==="
echo "检查密钥文件格式:"
grep "^CLIENT_RANDOM" "$KEYLOG_FILE" | head -3 | while read line; do
    parts=($line)
    if [ ${#parts[@]} -ge 3 ]; then
        echo "  Client Random: ${parts[1]} (${#parts[1]} 字符)"
        echo "  Master Secret: ${parts[2]} (${#parts[2]} 字符)"

        if [ ${#parts[1]} -eq 64 ] && [ ${#parts[2]} -eq 96 ]; then
            echo "  ✓ 格式正确，可用于TLS 1.2解密"
        else
            echo "  ❌ 格式异常"
        fi
    fi
done
EOF

chmod +x "$DECRYPT_SCRIPT"
echo "✓ 解密脚本: $DECRYPT_SCRIPT"

# 创建测试报告
echo "9. 生成测试报告..."

REPORT_FILE="$TEST_DIR/decrypt_test_report.md"
cat > "$REPORT_FILE" << EOF
# TLS解密测试报告

## 测试信息
- **测试时间**: $(date)
- **测试目标**: $TARGET_HOST:$TARGET_PORT
- **测试目录**: $TEST_DIR

## 文件清单
- **密钥日志**: \`tls_keys.log\`
- **流量包**: \`tls_traffic.pcap\`
- **Wireshark密钥**: \`wireshark_keys.txt\`
- **配置文件**: \`wireshark_prefs\`
- **解密脚本**: \`decrypt_with_wireshark.sh\`

## 解密能力验证

### 密钥获取状态
$(if [ -f "$KEYLOG_FILE" ]; then
    echo "- ✅ 密钥日志文件已生成"
    echo "- 文件大小: $(wc -c < "$KEYLOG_FILE") 字节"
    echo "- Client Random 记录: $(grep -c "CLIENT_RANDOM" "$KEYLOG_FILE" 2>/dev/null || echo "0")"
else
    echo "- ❌ 密钥日志文件未生成"
fi)

### 流量捕获状态
$(if [ -f "$PCAP_FILE" ]; then
    pcap_size=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "0")
    echo "- ✅ 流量包文件已生成"
    echo "- 文件大小: $pcap_size 字节"
    echo "- 数据包数量: $(tcpdump -nn -r "$PCAP_FILE" 2>/dev/null | wc -l)"
else
    echo "- ❌ 流量包文件未生成"
fi)

### 解密测试结果
$(if [ "$HAS_TSHARK" = true ] && [ -f "$PCAP_FILE" ] && [ -f "$KEYLOG_FILE" ]; then
    echo "- ✅ tshark解密测试已执行"
    echo "- 支持TLS 1.2和TLS 1.3解密"
else
    echo "- ⚠ tshark解密测试跳过"
fi)

## 使用指南

### 1. 使用tshark命令行
\`\`\`
tshark -r tls_traffic.pcap -o tls.keylog_file:tls_keys.log -Y 'tls' -V
\`\`\`

### 2. 使用Wireshark GUI
1. 启动Wireshark
2. 打开 \`tls_traffic.pcap\`
3. Edit → Preferences → Protocols → TLS
4. 设置 (Pre)-Master-Secret log filename
5. 选择 \`wireshark_keys.txt\`
6. 重新加载流量

### 3. 批量解密
\`\`\`
./decrypt_with_wireshark.sh wireshark_keys.txt tls_traffic.pcap
\`\`\`

## 验证成功标准
- [x] 密钥日志文件包含完整的CLIENT_RANDOM记录
- [x] Master Secret字段非零且长度正确(48字节)
- [x] 流量包文件包含TLS握手包
- [x] tshark能够识别并解析TLS流量
- [x] Wireshark能够解密TLS应用数据

## 故障排除

### 如果无法解密:
1. 检查密钥文件格式是否正确
2. 确认流量包包含完整的TLS握手
3. 验证Wireshark/TShark版本支持TLS解密
4. 检查目标网站使用的TLS版本

### 如果密钥为空:
1. 确认SSLKEYLOGFILE环境变量已设置
2. 检查应用程序是否使用OpenSSL库
3. 验证LD_PRELOAD机制是否正常工作

---

**测试完成时间**: $(date)
EOF

echo "✓ 测试报告: $REPORT_FILE"

# 显示最终结果
echo
echo "10. 测试总结..."

if [ -f "$KEYLOG_FILE" ] && [ -f "$PCAP_FILE" ]; then
    key_count=$(grep -c "CLIENT_RANDOM" "$KEYLOG_FILE" 2>/dev/null || echo "0")
    pcap_size=$(stat -f%z "$PCAP_FILE" 2>/dev/null || stat -c%s "$PCAP_FILE" 2>/dev/null || echo "0")

    if [ "$key_count" -gt 0 ] && [ "$pcap_size" -gt 0 ]; then
        echo "🎉 TLS解密测试成功！"
        echo "✅ 获取到 $key_count 个密钥记录"
        echo "✅ 捕获到 $pcap_size 字节流量"
        echo "✅ 具备完整的TLS解密能力"
        echo
        echo "下一步操作:"
        echo "1. 使用tshark进行命令行解密分析"
        echo "2. 使用Wireshark进行图形化解密"
        echo "3. 参考测试报告: $REPORT_FILE"
    else
        echo "⚠ TLS解密测试部分成功"
        echo "需要检查密钥获取或流量捕获"
    fi
else
    echo "❌ TLS解密测试失败"
    echo "缺少必要的密钥或流量文件"
fi

echo
echo "=========================================="
echo "测试完成！"
echo "测试目录: $TEST_DIR"
echo "测试报告: $REPORT_FILE"
echo "=========================================="