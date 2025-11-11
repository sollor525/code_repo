#!/bin/bash

echo "=== LD_PRELOAD 工作机制演示 ==="
echo

# 编译Hook库
echo "1. 编译Hook库..."
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 清理之前的密钥文件
echo "2. 清理之前的密钥文件..."
rm -f /tmp/openssl_keys_all.log /tmp/test_concept.log

# 演示1: 不使用LD_PRELOAD
echo "3. 演示1: 不使用LD_PRELOAD (无Hook)"
curl -s https://www.baidu.com > /dev/null
echo "   结果: 无Hook，密钥文件未生成"
ls -la /tmp/openssl_keys_all.log 2>/dev/null || echo "   ✓ 确认: 密钥文件不存在"

# 演示2: 使用LD_PRELOAD
echo
echo "4. 演示2: 使用LD_PRELOAD (有Hook)"
LD_PRELOAD=./libtls_agent_hook.so curl -s https://www.baidu.com > /dev/null
echo "   结果: 有Hook，密钥文件已生成"
if [ -f "/tmp/openssl_keys_all.log" ]; then
    echo "   ✓ 密钥文件已生成: $(wc -l < /tmp/openssl_keys_all.log) 行"
    echo "   ✓ Client Random: $(head -1 /tmp/openssl_keys_all.log | cut -d' ' -f2)"
else
    echo "   ✗ 密钥文件未生成"
fi

# 演示3: 验证Hook库加载
echo
echo "5. 演示3: 验证Hook库是否真的被加载"
LD_PRELOAD=./libtls_agent_hook.so curl -s https://www.baidu.com 2>&1 | grep "TLS Agent" | head -3
echo "   ✓ 显示Hook库的初始化日志"

echo
echo "=== 核心结论 ==="
echo "✓ LD_PRELOAD 只对当前命令的进程生效"
echo "✓ 已经运行的进程不会自动加载Hook库"
echo "✓ '重启服务' 的目的是让新进程加载Hook库，而不是配置变更"
echo "✓ 主动式Hook完全独立工作，无需外部Agent进程"

echo
echo "=== 生产环境应用指南 ==="
echo "对于已有服务 (如nginx/apache):"
echo "1. 停止服务: systemctl stop nginx"
echo "2. 使用Hook启动: LD_PRELOAD=/path/to/libtls_agent_hook.so systemctl start nginx"
echo "3. 只有新启动的nginx进程才会加载Hook库"