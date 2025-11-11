# TLS Key Agent 使用指南

## 快速开始

本指南将帮助您快速上手使用TLS Key Agent的主动式Hook功能来提取TLS密钥。

## 编译和安装

### 1. 编译Hook库

```bash
# 进入项目目录
cd tls_key_agent

# 编译C语言Hook库
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 编译Rust库（可选）
cargo build --release

# 编译测试程序
gcc -o test_hook_simple test_hook_simple.c -lssl -lcrypto
gcc -o test_compatibility test_compatibility.c -lssl -lcrypto
```

### 2. 验证编译结果

```bash
# 检查生成的文件
ls -la libtls_agent_hook.so
ls -la test_hook_simple test_compatibility
```

## 基本使用

### 方法1：监控命令行应用

```bash
# 监控curl请求
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com

# 监控wget下载
LD_PRELOAD=./libtls_agent_hook.so wget https://example.com

# 监控Python的HTTPS请求
LD_PRELOAD=./libtls_agent_hook.so python3 -c "import requests; requests.get('https://example.com')"

# 监控Node.js应用
LD_PRELOAD=./libtls_agent_hook.so node your_app.js
```

### 方法2：监控服务应用

```bash
# 监控Nginx
LD_PRELOAD=./libtls_agent_hook.so nginx -c /etc/nginx/nginx.conf

# 监控Apache
LD_PRELOAD=./libtls_agent_hook.so apache2ctl start

# 监控数据库（如果是TLS连接）
LD_PRELOAD=./libtls_agent_hook.so mysqld --ssl
```

### 方法3：监控现有进程

```bash
# 查找进程PID
ps aux | grep nginx

# 使用gdb加载Hook库（高级用法）
gdb -p <PID> -ex "handle SIG nostop noprint" -ex "set environment LD_PRELOAD=./libtls_agent_hook.so" -ex "continue"
```

## 密钥输出位置

### 默认输出文件

默认情况下，提取的密钥会保存在：

```bash
/tmp/openssl_keys_all.log
```

### 自定义输出文件

通过环境变量指定输出文件：

```bash
export SSLKEYLOGFILE=/tmp/my_tls_keys.log
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com
```

### 密钥文件格式

密钥文件使用Wireshark兼容格式：

```
CLIENT_RANDOM <32字节Client Random的十六进制> <48字节Master Secret的十六进制>
```

示例：
```
CLIENT_RANDOM 97413966f378bcf7731cb6adee286c328c46a8c6430c7605d9c1234ba1329f33 e8925d4c05772944de7a36a5a36f0887c3d85b1b6385501f1e4bae15c9e07cf12d47954846f7e908d7562142a0a6a927
```

## 测试和验证

### 1. 基础功能测试

```bash
# 运行基础测试
LD_PRELOAD=./libtls_agent_hook.so ./test_hook_simple

# 检查输出
echo "=== Hook初始化日志 ==="
grep "TLS Agent" /var/log/syslog 2>/dev/null || echo "查看控制台输出"

echo "=== 密钥文件检查 ==="
ls -la /tmp/openssl_keys_all.log /tmp/tls_test_keys.log 2>/dev/null || echo "密钥文件未创建"
```

### 2. 兼容性测试

```bash
# 运行兼容性测试
LD_PRELOAD=./libtls_agent_hook.so ./test_compatibility

# 检查OpenSSL版本兼容性
openssl version
echo "当前系统OpenSSL版本: $(openssl version)"
```

### 3. 性能测试

```bash
# 运行性能测试（可能产生大量日志）
LD_PRELOAD=./libtls_agent_hook.so ./test_performance > perf_test.log 2>&1

# 查看性能结果
echo "=== 性能测试结果 ==="
grep -E "(总耗时|平均每秒|每操作耗时)" perf_test.log || echo "查看完整日志文件"
```

## 实际应用场景

### 场景1：HTTPS流量分析

```bash
# 启动目标应用并监控
LD_PRELOAD=./libtls_agent_hook.so ./your_https_application

# 在另一个终端查看密钥
tail -f /tmp/openssl_keys_all.log

# 使用Wireshark解密流量
# 1. 在Wireshark中设置Protocol Preferences -> SSL -> (Pre)-Master-Secret log filename
# 2. 指定密钥文件路径：/tmp/openssl_keys_all.log
# 3. 重启Wireshark开始解密
```

### 场景2：调试TLS连接问题

```bash
# 设置详细日志
export RUST_LOG=debug

# 监控应用
LD_PRELOAD=./libtls_agent_hook.so your_application

# 分析密钥提取过程
grep "TLS Agent" /var/log/syslog | tail -20
```

### 场景3：安全测试

```bash
# 创建测试脚本
cat > test_tls_extraction.sh << 'EOF'
#!/bin/bash

echo "开始TLS密钥提取测试..."

# 清理之前的密钥文件
rm -f /tmp/test_keys.log

# 设置输出文件
export SSLKEYLOGFILE=/tmp/test_keys.log

# 运行多个HTTPS请求
for url in "https://google.com" "https://github.com" "https://stackoverflow.com"; do
    echo "测试: $url"
    LD_PRELOAD=./libtls_agent_hook.so curl -s $url > /dev/null
    sleep 1
done

# 检查结果
if [ -f "/tmp/test_keys.log" ]; then
    echo "✓ 成功提取密钥"
    echo "密钥条目数量: $(wc -l < /tmp/test_keys.log)"
    echo "文件大小: $(du -h /tmp/test_keys.log | cut -f1)"
else
    echo "✗ 未提取到密钥"
fi
EOF

chmod +x test_tls_extraction.sh
./test_tls_extraction.sh
```

## 故障排除

### 常见问题

#### 1. Hook库加载失败

**症状**：
```
error while loading shared libraries: libtls_agent_hook.so: cannot open shared object file
```

**解决方案**：
```bash
# 使用绝对路径
LD_PRELOAD=$(pwd)/libtls_agent_hook.so curl https://example.com

# 或将库复制到系统路径
sudo cp libtls_agent_hook.so /usr/local/lib/
sudo ldconfig
```

#### 2. 没有提取到密钥

**可能原因**：
- 应用没有进行TLS握手
- OpenSSL版本不兼容
- Hook时机不正确

**调试步骤**：
```bash
# 1. 检查Hook是否加载
LD_PRELOAD=./libtls_agent_hook.so your_app 2>&1 | grep "TLS Agent"

# 2. 检查OpenSSL版本
openssl version

# 3. 使用详细日志模式
LD_PRELOAD=./libtls_agent_hook.so strace -e write your_app 2>&1 | grep "TLS Agent"

# 4. 运行兼容性测试
LD_PRELOAD=./libtls_agent_hook.so ./test_compatibility
```

#### 3. 性能问题

**症状**：应用运行缓慢

**解决方案**：
```bash
# 1. 检查日志输出频率
# 如果有大量日志，考虑减少输出

# 2. 运行性能测试
LD_PRELOAD=./libtls_agent_hook.so ./test_performance

# 3. 检查系统资源
top -p $(pgrep your_app)
```

#### 4. 内存泄漏

**检测方法**：
```bash
# 使用valgrind检测内存泄漏
valgrind --leak-check=full --show-leak-kinds=all \
    LD_PRELOAD=./libtls_agent_hook.so ./test_hook_simple
```

### 调试技巧

#### 1. 启用详细日志

```bash
# 方法1：环境变量
export RUST_LOG=debug
LD_PRELOAD=./libtls_agent_hook.so your_app

# 方法2：查看系统日志
tail -f /var/log/syslog | grep "TLS Agent"
```

#### 2. 使用strace追踪

```bash
# 追踪系统调用
strace -f -e write,read,open,close \
    LD_PRELOAD=./libtls_agent_hook.so your_app 2>&1 | grep "TLS Agent"
```

#### 3. 使用ltrace追踪库调用

```bash
# 追踪库函数调用
ltrace -f -e fopen,fprintf,memcpy \
    LD_PRELOAD=./libtls_agent_hook.so your_app 2>&1
```

## 高级用法

### 1. 自定义Hook逻辑

```c
// 修改src/openssl_hook.c中的extract_tls_keys_proactive函数
// 添加自定义的密钥处理逻辑

static void custom_key_handler(const unsigned char *client_random,
                               const unsigned char *master_secret) {
    // 自定义处理逻辑
    // 例如：发送到远程服务器、写入数据库等
}
```

### 2. 集成到现有系统

```bash
# 方法1：修改启动脚本
echo 'export LD_PRELOAD=/path/to/libtls_agent_hook.so' >> /etc/profile

# 方法2：创建systemd服务
sudo tee /etc/systemd/system/tls-key-agent.service > /dev/null <<EOF
[Unit]
Description=TLS Key Agent Hook
After=network.target

[Service]
Type=oneshot
Environment=LD_PRELOAD=/path/to/libtls_agent_hook.so
ExecStart=/usr/bin/your_application
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable tls-key-agent
sudo systemctl start tls-key-agent
```

### 3. 批量监控

```bash
# 创建批量监控脚本
cat > monitor_multiple.sh << 'EOF'
#!/bin/bash

APPS=("nginx" "apache2" "mysqld" "postgresql")

for app in "${APPS[@]}"; do
    if pgrep $app > /dev/null; then
        echo "监控 $app..."
        sudo LD_PRELOAD=/path/to/libtls_agent_hook.so systemctl restart $app
    else
        echo "$app 未运行"
    fi
done
EOF

chmod +x monitor_multiple.sh
sudo ./monitor_multiple.sh
```

## 安全注意事项

### 1. 权限控制

```bash
# 限制密钥文件访问权限
chmod 600 /tmp/openssl_keys_all.log
chown $USER:$USER /tmp/openssl_keys_all.log

# 使用安全目录
export SSLKEYLOGFILE=/var/log/tls_keys/secure_keys.log
mkdir -p /var/log/tls_keys/
chmod 700 /var/log/tls_keys/
```

### 2. 数据保护

```bash
# 加密密钥文件（可选）
gpg --symmetric --cipher-algo AES256 /tmp/openssl_keys_all.log

# 安全删除密钥文件
shred -u /tmp/openssl_keys_all.log
```

### 3. 审计记录

```bash
# 记录Hook使用情况
echo "$(date): LD_PRELOAD used by $USER for $APP" >> /var/log/tls_agent_audit.log
```

## 性能优化建议

1. **减少日志输出**：在生产环境中减少详细日志
2. **使用SSD存储**：密钥文件频繁写入，使用SSD提高性能
3. **限制监控范围**：只监控必要的应用
4. **定期清理密钥文件**：避免密钥文件过大
5. **监控内存使用**：确保没有内存泄漏

## 总结

TLS Key Agent的主动式Hook功能提供了一个强大、灵活的TLS密钥提取解决方案。通过遵循本指南，您可以：

- ✅ 快速部署和使用Hook功能
- ✅ 监控各种TLS应用的密钥提取
- ✅ 进行故障排除和性能优化
- ✅ 在生产环境中安全使用

如有问题，请参考技术文档 `PROACTIVE_HOOK_DESIGN.md` 或提交Issue。