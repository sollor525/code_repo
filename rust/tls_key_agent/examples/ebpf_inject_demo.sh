#!/bin/bash

# eBPF + 动态注入组合使用演示
# 这个脚本演示了如何在不重启服务的情况下监控TLS密钥

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== TLS Key Agent eBPF + 动态注入演示 ===${NC}"

# 检查权限
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}此演示需要root权限${NC}"
    echo "请使用: sudo $0"
    exit 1
fi

# 演示目录
DEMO_DIR="/tmp/tls_agent_demo"
mkdir -p "$DEMO_DIR"

echo -e "${GREEN}步骤1: 启动一些测试TLS服务${NC}"

# 启动nginx服务（如果没有运行）
if ! pgrep nginx > /dev/null; then
    echo "启动nginx..."
    nginx -t && nginx || echo "nginx启动失败，继续演示..."
fi

# 启动一些测试的Python HTTPS服务器
echo "启动测试HTTPS服务器..."
cat > "$DEMO_DIR/test_server.py" << 'EOF'
#!/usr/bin/env python3
import ssl
import http.server
import socketserver

class TestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Hello TLS World!')

# 创建SSL上下文
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/etc/ssl/certs/ssl-cert-snakeoil.pem')
context.load_privatekey('/etc/ssl/private/ssl-cert-snakeoil.key')

# 启动服务器
with socketserver.TCPServer(("", 8443), TestHandler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("HTTPS服务器启动在端口8443")
    httpd.serve_forever()
EOF

chmod +x "$DEMO_DIR/test_server.py"
nohup python3 "$DEMO_DIR/test_server.py" > "$DEMO_DIR/test_server.log" 2>&1 &
TEST_SERVER_PID=$!
echo "测试HTTPS服务器 PID: $TEST_SERVER_PID"

echo -e "${GREEN}步骤2: 编译项目${NC}"

# 编译项目
cd "$(dirname "$0")/.."
echo "编译TLS Key Agent..."
cargo build --release --features test-utils

echo -e "${GREEN}步骤3: 发现TLS进程${NC}"

# 发现系统中的TLS进程
echo "当前系统中的TLS进程:"
./target/release/dynamic_injector discover --format table

echo -e "${GREEN}步骤4: 执行动态注入${NC}"

# 显示即将注入的进程
echo "将要注入Hook的TLS进程:"
./target/release/dynamic_injector discover --format table | grep -E "(PID|.*1.*0)"

echo -e "${YELLOW}确认要注入Hook吗？(y/N)${NC}"
read -r response

if [[ "$response" =~ ^[Yy]$ ]]; then
    echo "执行动态注入..."
    ./target/release/dynamic_injector inject-all \
        --library ./target/release/libopenssl_hook.so \
        --skip "$TEST_SERVER_PID"  # 跳过测试服务器
else
    echo "跳过注入步骤"
fi

echo -e "${GREEN}步骤5: 启动TLS密钥收集${NC}"

# 启动TLS Key Agent
cat > "$DEMO_DIR/collector_config.toml" << 'EOF'
[agent]
name = "tls_collector"
log_level = "info"

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true

[transport]
enabled_transports = ["File"]

[transport.file]
enabled = true
directory = "/tmp/tls_agent_demo/keys"
filename_pattern = "tls_keys_{timestamp}.log"
max_file_size = "10MB"
max_files = 5
EOF

mkdir -p "$DEMO_DIR/keys"

echo "启动TLS密钥收集器..."
nohup ./target/release/tls_key_agent \
    --config "$DEMO_DIR/collector_config.toml" \
    > "$DEMO_DIR/collector.log" 2>&1 &
COLLECTOR_PID=$!
echo "收集器 PID: $COLLECTOR_PID"

echo -e "${GREEN}步骤6: 生成TLS流量进行测试${NC}"

sleep 2  # 等待收集器启动

# 测试nginx HTTPS
echo "测试nginx HTTPS连接..."
curl -s -k https://localhost:443 > /dev/null || echo "nginx HTTPS测试失败"

# 测试我们的HTTPS服务器
echo "测试自定义HTTPS服务器..."
curl -s -k https://localhost:8443 > /dev/null || echo "自定义HTTPS服务器测试失败"

# 使用openssl命令测试
echo "使用openssl测试TLS连接..."
echo -e "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" | \
    openssl s_client -connect localhost:443 -quiet > /dev/null 2>&1 || \
    echo "openssl测试失败"

echo -e "${GREEN}步骤7: 检查收集到的密钥${NC}"

sleep 3  # 等待密钥处理

echo "检查密钥日志文件:"
if ls "$DEMO_DIR/keys"/*.log 1> /dev/null 2>&1; then
    for log_file in "$DEMO_DIR"/keys/*.log; do
        echo "=== $(basename "$log_file") ==="
        if [[ -s "$log_file" ]]; then
            tail -10 "$log_file"
        else
            echo "文件为空"
        fi
        echo
    done
else
    echo "没有找到密钥日志文件"
fi

echo -e "${GREEN}步骤8: 验证Hook状态${NC}"

echo "重新检查进程Hook状态:"
./target/release/dynamic_injector discover --format table

echo -e "${GREEN}步骤9: 清理演示环境${NC}"

# 清理进程
echo "清理测试进程..."
[[ -n "$TEST_SERVER_PID" ]] && kill "$TEST_SERVER_PID" 2>/dev/null || true
[[ -n "$COLLECTOR_PID" ]] && kill "$COLLECTOR_PID" 2>/dev/null || true

# 等待进程完全退出
sleep 2

echo -e "${GREEN}演示完成！${NC}"

# 显示结果摘要
echo -e "${BLUE}=== 演示结果摘要 ===${NC}"
echo "演示目录: $DEMO_DIR"
echo "日志文件:"
echo "  - 收集器日志: $DEMO_DIR/collector.log"
echo "  - 测试服务器日志: $DEMO_DIR/test_server.log"
echo "  - 密钥日志目录: $DEMO_DIR/keys/"

# 检查是否有密钥被收集
KEY_COUNT=0
if ls "$DEMO_DIR/keys"/*.log 1> /dev/null 2>&1; then
    KEY_COUNT=$(grep -c "CLIENT_RANDOM\|TRAFFIC_SECRET" "$DEMO_DIR"/keys/*.log 2>/dev/null || echo "0")
fi

if [[ $KEY_COUNT -gt 0 ]]; then
    echo -e "${GREEN}✅ 成功收集到 $KEY_COUNT 个密钥事件${NC}"
else
    echo -e "${YELLOW}⚠️  没有收集到密钥事件，可能需要检查Hook注入状态${NC}"
fi

echo
echo -e "${BLUE}=== 后续操作建议 ===${NC}"
echo "1. 查看密钥日志: cat $DEMO_DIR/keys/*.log"
echo "2. 检查收集器日志: cat $DEMO_DIR/collector.log"
echo "3. 验证Hook状态: ./target/release/dynamic_injector discover"
echo "4. 使用生产部署脚本: sudo ./scripts/ebpf_inject_combo.sh"
echo
echo -e "${BLUE}清理事示环境: rm -rf $DEMO_DIR${NC}"