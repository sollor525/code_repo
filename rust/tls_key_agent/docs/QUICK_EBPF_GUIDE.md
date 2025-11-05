# eBPF + 动态注入快速使用指南

## 🚀 快速开始

这个指南将帮助您快速使用eBPF + 动态注入组合来监控TLS密钥，无需重启服务！

### 1. 编译项目

```bash
# 编译简化版注入器（推荐）
cargo build --release --bin simple_injector

# 编译主程序
cargo build --release --features test-utils
```

### 2. 发现TLS进程

```bash
# 发现系统中的TLS进程
./target/release/simple_injector discover

# 输出示例：
PID      Name             CmdLine              TLS    Hooked   LibSSL
----------------------------------------------------------------------------------------------------
453      sshd             sshd: /usr/sbin/s... true   false    /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1
1234     nginx           nginx: master pro... true   false    /usr/lib/x86_64-linux-gnu/libssl.so.1.1
```

### 3. 动态注入Hook

```bash
# 注入到指定进程（以ssh进程为例）
./target/release/simple_injector inject \
    --pid 453 \
    --library ./target/release/libopenssl_hook.so

# 成功输出：
[2023-11-05 15:00:00] 开始注入Hook库到进程 453
[2023-11-05 15:00:01] 使用gdb注入到进程 453
[2023-11-05 15:00:02] gdb注入成功
[2023-11-05 15:00:02] 成功注入Hook库到进程 453
```

### 4. 启动密钥收集

```bash
# 启动TLS Key Agent
./target/release/tls_key_agent --config config.toml &
```

### 5. 生成TLS流量测试

```bash
# 创建新的SSH连接触发TLS握手
ssh localhost "echo 'Hello TLS'"

# 或者使用curl测试HTTPS
curl -s -k https://example.com > /dev/null
```

### 6. 检查密钥提取结果

```bash
# 查看提取的密钥
tail -f /var/log/tls_agent/tls_keys_*.log

# 预期输出示例：
[2023-11-05 15:01:00] TLS_KEY | session-id | 127.0.0.1:12345 -> 127.0.0.1:22 | Process: sshd (PID: 453) | ClientRandom: abcdef123456... | MasterSecret: fedcba654321...
```

## 📊 使用场景示例

### 场景1: 监控SSH服务

```bash
# 1. 发现SSH进程
./target/release/simple_injector discover | grep sshd

# 2. 注入Hook
./target/release/simple_injector inject \
    --pid $(pgrep sshd | head -1) \
    --library ./target/release/libopenssl_hook.so

# 3. 触发SSH连接测试
ssh localhost "date"

# 4. 检查密钥日志
tail -20 /var/log/tls_agent/tls_keys_*.log
```

### 场景2: 监控Nginx HTTPS

```bash
# 1. 启动Nginx（如果未运行）
sudo nginx -t && sudo nginx

# 2. 发现Nginx进程
./target/release/simple_injector discover | grep nginx

# 3. 注入Hook到所有Nginx进程
for pid in $(pgrep nginx); do
    ./target/release/simple_injector inject \
        --pid $pid \
        --library ./target/release/libopenssl_hook.so
done

# 4. 测试HTTPS连接
curl -s -k https://localhost > /dev/null

# 5. 验证Hook状态
./target/release/simple_injector discover | grep nginx
```

### 场景3: 批量监控所有TLS服务

```bash
# 创建批量注入脚本
cat > inject_all.sh << 'EOF'
#!/bin/bash
LIBRARY="./target/release/libopenssl_hook.so"

# 发现所有TLS进程并注入
./target/release/simple_injector discover | \
    awk '/true.*false/ {print $1}' | \
    while read pid; do
        echo "注入进程 $pid..."
        ./target/release/simple_injector inject \
            --pid $pid \
            --library $LIBRARY
    done

echo "批量注入完成！"
EOF

chmod +x inject_all.sh

# 执行批量注入
sudo ./inject_all.sh
```

## 🔧 实用技巧

### 1. 过滤特定进程

```bash
# 只显示Web服务器进程
./target/release/simple_injector discover | grep -E "nginx|apache|httpd"

# 只显示数据库进程
./target/release/simple_injector discover | grep -E "mysql|postgres|redis"
```

### 2. JSON格式输出

```bash
# JSON格式输出，便于脚本处理
./target/release/simple_injector discover --format json

# 使用jq处理JSON输出
./target/release/simple_injector discover --format json | \
  jq '.[] | select(.uses_tls == true and .is_hooked == false) | .pid'
```

### 3. 自动化脚本

```bash
# 创建自动化监控脚本
cat > auto_monitor.sh << 'EOF'
#!/bin/bash
LIBRARY="./target/release/libopenssl_hook.so"
LOG_FILE="/var/log/tls_agent/auto_monitor.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "开始自动监控TLS进程"

# 持续监控
while true; do
    # 发现未Hook的TLS进程
    UNHOOKED_PIDS=$(./target/release/simple_injector discover --format json | \
        jq -r '.[] | select(.uses_tls == true and .is_hooked == false) | .pid')

    if [ -n "$UNHOOKED_PIDS" ]; then
        echo "$UNHOOKED_PIDS" | while read pid; do
            log "发现未Hook的TLS进程: $pid"
            if ./target/release/simple_injector inject \
                --pid $pid \
                --library $LIBRARY; then
                log "成功注入进程 $pid"
            else
                log "注入进程 $pid 失败"
            fi
        done
    fi

    # 每30秒检查一次
    sleep 30
done
EOF

chmod +x auto_monitor.sh

# 启动自动监控
sudo ./auto_monitor.sh &
```

## 🛠️ 故障排除

### 1. GDB注入失败

**问题**: gdb注入失败

**解决方案**:
```bash
# 检查gdb是否安装
which gdb

# 安装gdb
sudo apt-get install gdb  # Ubuntu/Debian
sudo yum install gdb      # CentOS/RHEL

# 检查权限
sudo ./target/release/simple_injector inject --pid <PID> --library <LIBRARY>
```

### 2. 进程不存在

**问题**: 进程PID不存在

**解决方案**:
```bash
# 检查进程是否还存在
ps -p <PID> || echo "进程不存在"

# 重新发现进程
./target/release/simple_injector discover | grep <进程名>
```

### 3. Hook库文件不存在

**问题**: Hook库文件不存在

**解决方案**:
```bash
# 检查文件是否存在
ls -la ./target/release/libopenssl_hook.so

# 重新编译
cargo build --release
```

### 4. 没有提取到密钥

**问题**: 注入成功但没有密钥输出

**解决方案**:
```bash
# 1. 检查TLS Key Agent是否运行
ps aux | grep tls_key_agent

# 2. 检查配置文件
cat config.toml | grep -A5 "\[transport\]"

# 3. 检查输出目录
ls -la /var/log/tls_agent/

# 4. 手动触发TLS连接
curl -v https://example.com 2>&1 | grep -i ssl
```

## 📈 效果验证

### 验证Hook状态

```bash
# 注入前
./target/release/simple_injector discover | grep nginx
# 输出: 1234 nginx ... false

# 注入后
./target/release/simple_injector discover | grep nginx
# 输出: 1234 nginx ... true
```

### 验证密钥提取

```bash
# 启动监控
tail -f /var/log/tls_agent/tls_keys_*.log &

# 触发TLS连接
ssh localhost "echo test"

# 检查日志输出
grep -i "TLS_KEY\|Client_Random" /var/log/tls_agent/tls_keys_*.log
```

## 🎯 最佳实践

1. **测试环境先验证**: 在测试环境验证注入效果
2. **分批注入**: 避免一次性注入太多进程
3. **监控影响**: 注入后监控系统性能和稳定性
4. **日志记录**: 保留详细的注入和密钥提取日志
5. **权限控制**: 仅在必要时使用root权限

---

**🎉 恭喜！您现在可以使用eBPF + 动态注入组合来监控TLS密钥了！**

这种方法可以：
- ✅ 无需重启服务
- ✅ 实时监控新TLS连接
- ✅ 支持多种TLS应用
- ✅ 高效安全的密钥提取