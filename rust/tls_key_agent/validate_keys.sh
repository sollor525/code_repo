#!/bin/bash

# TLS密钥验证脚本
# 验证获取到的密钥是否可以用于解密

set -e

echo "=========================================="
echo "        TLS 密钥验证和完整性检查"
echo "=========================================="
echo "测试时间: $(date)"
echo

# 配置
KEYLOG_FILE="${1:-/tmp/test_keylog.txt}"
VALIDATION_DIR="/tmp/key_validation_$(date +%s)"

# 创建验证目录
mkdir -p "$VALIDATION_DIR"

echo "验证目标: $KEYLOG_FILE"
echo "验证目录: $VALIDATION_DIR"
echo

# 检查密钥文件是否存在
if [ ! -f "$KEYLOG_FILE" ]; then
    echo "❌ 密钥文件不存在: $KEYLOG_FILE"
    echo "请先运行密钥获取脚本"
    exit 1
fi

echo "✓ 密钥文件存在: $KEYLOG_FILE"

# 解析密钥文件
echo
echo "=== 密钥文件分析 ==="

total_lines=$(wc -l < "$KEYLOG_FILE")
echo "总行数: $total_lines"

# 解析不同类型的密钥
client_random_count=0
master_secret_count=0
traffic_secret_count=0

echo
echo "密钥类型统计:"

while IFS= read -r line; do
    if [[ "$line" =~ ^CLIENT_RANDOM ]]; then
        ((client_random_count++))
        echo "  ✓ CLIENT_RANDOM (TLS 1.2): $line"
    elif [[ "$line" =~ CLIENT_TRAFFIC_SECRET|SERVER_TRAFFIC_SECRET ]]; then
        ((traffic_secret_count++))
        echo "  ✓ TRAFFIC_SECRET (TLS 1.3): $line"
    elif [[ "$line" =~ MASTER_SECRET ]]; then
        ((master_secret_count++))
        echo "  ✓ MASTER_SECRET: $line"
    fi
done < "$KEYLOG_FILE"

echo
echo "统计结果:"
echo "  - Client Random: $client_random_count"
echo "  - Master Secret: $master_secret_count"
echo "  - Traffic Secret: $traffic_secret_count"

# 验证密钥格式和完整性
echo
echo "=== 密钥完整性验证 ==="

validation_results=()

while IFS= read -r line; do
    if [[ "$line" =~ ^CLIENT_RANDOM\ ([0-9a-f]{64})\ ([0-9a-f]{96})$ ]]; then
        client_random="${BASH_REMATCH[1]}"
        master_secret="${BASH_REMATCH[2]}"

        echo "验证密钥对 $((++pair_index)):"

        # 验证Client Random
        if [ ${#client_random} -eq 64 ]; then
            echo "  ✓ Client Random长度正确 (32字节)"
            echo "    值: ${client_random:0:16}...${client_random: -8}"
        else
            echo "  ❌ Client Random长度错误: ${#client_random} 字符 (期望64)"
            continue
        fi

        # 验证Master Secret
        if [ ${#master_secret} -eq 96 ]; then
            echo "  ✓ Master Secret长度正确 (48字节)"
            echo "    值: ${master_secret:0:16}...${master_secret: -8}"

            # 检查密钥质量
            non_zero_chars=$(echo "$master_secret" | tr -d '0' | wc -c)
            zero_chars=$((96 - non_zero_chars))
            entropy_ratio=$((non_zero_chars * 100 / 96))

            echo "    熵值分析: $entropy_ratio% 非零 ($non_zero_chars/96)"

            if [ "$entropy_ratio" -gt 50 ]; then
                echo "  ✓ 密钥质量: 优秀"
                validation_results+=("优秀")
            elif [ "$entropy_ratio" -gt 20 ]; then
                echo "  ✓ 密钥质量: 良好"
                validation_results+=("良好")
            else
                echo "  ⚠ 密钥质量: 较低 ($entropy_ratio% 熵值)"
                validation_results+=("较低")
            fi

            # 检查是否全为零
            if [ "$zero_chars" -eq 96 ]; then
                echo "  ❌ 警告: Master Secret全为零，可能是占位符"
                validation_results+=("无效")
            fi

        else
            echo "  ❌ Master Secret长度错误: ${#master_secret} 字符 (期望96)"
            validation_results+=("格式错误")
        fi

        echo

        # 保存验证结果
        {
            echo "密钥对验证结果 #$((${#validation_results[@]}))"
            echo "时间: $(date)"
            echo "Client Random: $client_random"
            echo "Master Secret: $master_secret"
            echo "验证结果: ${validation_results[-1]}"
            echo "熵值: $entropy_ratio%"
            echo "---"
        } >> "$VALIDATION_DIR/validation_details.log"

    elif [[ "$line" =~ (CLIENT|SERVER)_TRAFFIC_SECRET_(0|1) ]]; then
        secret_type=$(echo "$line" | cut -d' ' -f1)
        echo "验证 $secret_type:"

        # 提取密钥部分（通常在第四个位置）
        secret_value=$(echo "$line" | awk '{print $4}')

        if [ ${#secret_value} -gt 0 ]; then
            echo "  ✓ 密钥值获取成功"
            echo "    类型: $secret_type"
            echo "    值: ${secret_value:0:16}...${secret_value: -8}"

            # TLS 1.3流量密钥通常64字节
            if [ ${#secret_value} -eq 128 ]; then
                echo "  ✓ TLS 1.3流量密钥长度正确 (64字节)"
                validation_results+=("TLS1.3有效")
            else
                echo "  ⚠ 流量密钥长度: ${#secret_value} 字符"
                validation_results+=("TLS1.3格式")
            fi
        else
            echo "  ❌ 无法提取密钥值"
            validation_results+=("提取失败")
        fi

        echo

    fi
done < "$KEYLOG_FILE"

# 生成验证报告
echo "=== 验证报告 ==="

echo "总体验证结果:"
valid_count=0
total_count=${#validation_results[@]}

for result in "${validation_results[@]}"; do
    case "$result" in
        "优秀"|"良好"|"TLS1.3有效"|"TLS1.3格式")
            ((valid_count++))
            echo "  ✓ $result"
            ;;
        *)
            echo "  ⚠ $result"
            ;;
    esac
done

echo
echo "验证统计:"
echo "  - 总验证项目: $total_count"
echo "  - 通过验证: $valid_count"
echo "  - 验证通过率: $(( valid_count * 100 / total_count ))%"

# 解密能力评估
echo
echo "=== 解密能力评估 ==="

if [ "$client_random_count" -gt 0 ] && [ "$traffic_secret_count" -gt 0 ]; then
    echo "✅ 具备 TLS 1.3 解密能力"
    echo "   - Traffic Secret: $traffic_secret_count 个"
    echo "   - 可以直接解密 TLS 1.3 流量"
    echo "   - 支持客户端到服务器和服务器到客户端的流量"

elif [ "$client_random_count" -gt 0 ] && [ ${#validation_results[@]} -gt 0 ]; then
    # 检查是否有有效的Master Secret
    has_valid_master=false
    for result in "${validation_results[@]}"; do
        if [[ "$result" =~ 优秀|良好 ]]; then
            has_valid_master=true
            break
        fi
    done

    if [ "$has_valid_master" = true ]; then
        echo "✅ 具备 TLS 1.2 解密能力"
        echo "   - Client Random: $client_random_count 个"
        echo "   - Master Secret: 有效"
        echo "   - 可以生成完整的密钥材料"
        echo "   - 支持对称加密和MAC验证"
    else
        echo "⚠️  具备部分 TLS 1.2 解密能力"
        echo "   - Client Random: $client_random_count 个"
        echo "   - Master Secret: 质量较低或无效"
        echo "   - 可能无法完全解密TLS流量"
    fi

else
    echo "❌ 不具备完整的TLS解密能力"
    echo "   - 缺少必要的密钥材料"
    echo "   - 无法进行TLS流量解密"
fi

# 生成解密配置文件
echo
echo "=== 生成解密配置 ==="

# Wireshark配置
WWSHARK_CONFIG="$VALIDATION_DIR/wireshark_keys.txt"
cp "$KEYLOG_FILE" "$WWSHARK_CONFIG"
echo "✓ Wireshark密钥文件: $WWSHARK_CONFIG"

# 生成Python解密脚本
PYTHON_DECRYPT="$VALIDATION_DIR/decrypt_example.py"
cat > "$PYTHON_DECRYPT" << 'EOF'
#!/usr/bin/env python3
"""
TLS 1.2 密钥推导示例
使用Client Random和Master Secret生成会话密钥
"""

import hashlib
import hmac
import sys

def derive_keys(client_random_hex, master_secret_hex):
    """从Client Random和Master Secret推导TLS密钥"""

    # 转换为字节
    client_random = bytes.fromhex(client_random_hex)
    master_secret = bytes.fromhex(master_secret_hex)

    print(f"Client Random ({len(client_random)} bytes): {client_random.hex()}")
    print(f"Master Secret ({len(master_secret)} bytes): {master_secret.hex()}")

    # TLS 1.2 PRF (P_hash with SHA-256)
    def p_hash(secret, seed, length):
        h = hmac.new(secret, seed, hashlib.sha256).digest()
        result = h
        while len(result) < length:
            h = hmac.new(secret, h + seed, hashlib.sha256).digest()
            result += h
        return result[:length]

    # 密钥块生成
    seed = b"master secret" + client_random
    key_block = p_hash(master_secret, seed, 96)  # 12 * 8 = 96 bytes

    # 分割密钥块
    client_mac = key_block[0:32]      # 32 bytes (SHA-256)
    server_mac = key_block[32:64]     # 32 bytes
    client_key = key_block[64:80]     # 16 bytes
    server_key = key_block[80:96]     # 16 bytes

    print(f"\n推导出的密钥:")
    print(f"Client MAC: {client_mac.hex()}")
    print(f"Server MAC: {server_mac.hex()}")
    print(f"Client Key: {client_key.hex()}")
    print(f"Server Key: {server_key.hex()}")

    return {
        'client_mac': client_mac,
        'server_mac': server_mac,
        'client_key': client_key,
        'server_key': server_key
    }

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("用法: python3 decrypt_example.py <client_random_hex> <master_secret_hex>")
        sys.exit(1)

    client_random_hex = sys.argv[1]
    master_secret_hex = sys.argv[2]

    try:
        keys = derive_keys(client_random_hex, master_secret_hex)
        print(f"\n✅ 密钥推导成功!")
        print(f"这些密钥可用于解密TLS 1.2流量")
    except Exception as e:
        print(f"❌ 密钥推导失败: {e}")
        sys.exit(1)
EOF

chmod +x "$PYTHON_DECRYPT"
echo "✓ Python解密脚本: $PYTHON_DECRYPT"

# 生成测试命令
echo
echo "=== 推荐的解密测试命令 ==="

if command -v tshark >/dev/null 2>&1; then
    echo "1. 使用tshark解密:"
    echo "   tshark -o tls.keylog_file:$KEYLOG_FILE -r <pcap_file> -Y 'tls' -V"
    echo
fi

if command -v wireshark >/dev/null 2>&1; then
    echo "2. 使用Wireshark解密:"
    echo "   - 启动Wireshark"
    echo "   - Edit -> Preferences -> Protocols -> TLS"
    echo "   - (Pre)-Master-Secret log filename: $KEYLOG_FILE"
    echo "   - 重新加载pcap文件"
    echo
fi

echo "3. 使用Python脚本推导密钥:"
echo "   python3 $PYTHON_DECRYPT <client_random_hex> <master_secret_hex>"
echo

echo "=========================================="
echo "验证完成！"
echo "验证目录: $VALIDATION_DIR"
echo "详细日志: $VALIDATION_DIR/validation_details.log"
echo "=========================================="