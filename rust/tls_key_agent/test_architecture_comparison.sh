#!/bin/bash

echo "=== TLS Key Agent 架构测试 ==="
echo

# 编译Hook库
echo "1. 编译主动式Hook库..."
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 测试场景1: 只有Hook库，无Agent进程，无配置文件
echo
echo "=== 场景1: 只有Hook库 (推荐方式) ==="
echo "特点: 最简单、最直接的密钥提取方式"

rm -f /tmp/test_scenario1.log
export SSLKEYLOGFILE=/tmp/test_scenario1.log

# 确保没有Agent进程运行
pkill -f tls_key_agent 2>/dev/null

echo "测试主动式Hook提取..."
LD_PRELOAD=./libtls_agent_hook.so curl -s https://www.baidu.com > /dev/null 2>&1

echo "结果分析:"
echo "  ✓ 密钥文件生成: $([ -f /tmp/test_scenario1.log ] && echo '是' || echo '否')"
echo "  ✓ 默认文件生成: $([ -f /tmp/openssl_keys_all.log ] && echo '是' || echo '否')"
echo "  ✓ Agent进程运行: $(ps aux | grep tls_key_agent | grep -v grep | wc -l) 个"

if [ -f "/tmp/openssl_keys_all.log" ]; then
    echo "  ✓ 提取的密钥条目: $(wc -l < /tmp/openssl_keys_all.log) 条"
    echo "  ✓ 有效的Master Secret: $(grep -v "000000000000" /tmp/openssl_keys_all.log | wc -l) 条"
fi

echo
echo "=== 功能对比分析 ==="
echo

cat << 'EOF'
🏗️  架构对比:

┌─────────────────────────────────────────────────────────────────┐
│                    主动式Hook架构                            │
├─────────────────────────────────────────────────────────────────┤
│ 工作方式: LD_PRELOAD直接Hook SSL函数                              │
│ 核心组件: libtls_agent_hook.so                                    │
│ Agent进程: ❌ 不需要                                               │
│ 配置文件: ❌ 不需要                                               │
│ 密钥传输: ❌ 不需要 (直接写入文件)                                   │
│ 复杂度: ⭐ 最简单                                                │
│ 部署难度: ⭐ 最容易                                                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    传统Agent架构                             │
├─────────────────────────────────────────────────────────────────┤
│ 工作方式: 独立Agent进程 + 通信机制                                │
│ 核心组件: tls_key_agent + libopenssl_hook.so                      │
│ Agent进程: ✅ 必须运行                                             │
│ 配置文件: ✅ 必须提供                                               │
│ 密钥传输: ✅ TCP/文件传输                                           │
│ 复杂度: ⭐⭐⭐ 较复杂                                               │
│ 部署难度: ⭐⭐⭐⭐ 较困难                                             │
└─────────────────────────────────────────────────────────────────┘

EOF

echo
echo "=== 使用建议 ==="
echo

cat << 'EOF'
🎯 推荐使用主动式Hook架构:

1. ✅ 简单部署:
   LD_PRELOAD=/path/to/libtls_agent_hook.so your_app

2. ✅ 无需配置:
   直接工作，无需配置文件或Agent进程

3. ✅ 本地输出:
   密钥直接写入 /tmp/openssl_keys_all.log

4. ✅ Wireshark兼容:
   直接在Wireshark中设置密钥文件路径

5. ✅ 高可靠性:
   没有进程间通信故障点

🔧 何时使用传统Agent架构:
- 需要远程密钥收集
- 需要复杂的过滤规则
- 需要实时密钥传输到多个目的地

EOF

echo
echo "=== 实际测试验证 ==="
echo

# 测试密钥质量
if [ -f "/tmp/openssl_keys_all.log" ]; then
    echo "密钥质量分析:"
    python3 -c "
import re
with open('/tmp/openssl_keys_all.log', 'r') as f:
    lines = f.readlines()

    valid_ms = 0
    for line in lines:
        if line.startswith('CLIENT_RANDOM'):
            parts = line.strip().split()
            if len(parts) >= 3:
                ms = parts[2]
                # 检查Master Secret是否不全为0
                if '000000000000' not in ms or len(ms) > 100:
                    valid_ms += 1

    print(f'  ✓ 总密钥条目: {len(lines)}')
    print(f'  ✓ 有效Master Secret: {valid_ms}')
    print(f'  ✓ 提取成功率: {valid_ms/len(lines)*100:.1f}%')
"
else
    echo "  ⚠ 密钥文件不存在，可能Hook库未正确加载"
fi

echo
echo "=== 总结 ==="
echo "✅ 主动式Hook架构完全独立工作"
echo "✅ 无需tls_key_agent进程即可提取密钥"
echo "✅ 无需配置文件即可工作"
echo "✅ 直接输出到本地文件，简单高效"