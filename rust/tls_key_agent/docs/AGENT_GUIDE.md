# TLS Key Agent 完整指南

## 🎯 Agent进程 vs Hook库架构选择

TLS Key Agent提供**两种架构模式**，根据需求选择：

### 🚀 模式1: 仅Hook库 (推荐90%用户)

**特点：** 极简部署，无需Agent进程

```bash
# 一条命令搞定
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com
cat /tmp/openssl_keys_all.log
```

**优势：**
- ✅ 零配置：无需配置文件
- ✅ 零依赖：无需额外进程
- ✅ 高性能：直接Hook，无中间层
- ✅ 高可靠：无进程间通信故障点

**适用场景：**
- 个人开发和调试
- 安全渗透测试
- Wireshark流量解密
- 单机密钥收集

### 🏢 模式2: Agent + Hook组合 (企业级)

**特点：** 完整的企业级密钥管理解决方案

```bash
# 1. 启动Agent进程
./target/release/tls_key_agent --config agent_config.toml &

# 2. 应用使用Hook库
LD_PRELOAD=./libtls_agent_hook.so your_application
```

**企业级功能：**
- ✅ **集中管理**: TOML配置文件驱动的规则管理
- ✅ **远程收集**: TCP传输到中央服务器
- ✅ **复杂过滤**: 五元组、进程名、时间范围过滤
- ✅ **实时监控**: Agent状态和性能监控
- ✅ **高可用**: 故障转移和自动重启
- ✅ **文件轮转**: 自动日志文件管理

**适用场景：**
- 企业级部署
- 分布式密钥收集
- 集中化监控
- 合规性要求

## 🚀 快速部署

### 选项1: 仅Hook库部署 (推荐)

```bash
# 1. 编译Hook库
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 2. 部署到系统
sudo cp libtls_agent_hook.so /usr/local/lib/
sudo chmod 644 /usr/local/lib/libtls_agent_hook.so

# 3. 立即使用
LD_PRELOAD=/usr/local/lib/libtls_agent_hook.so your_https_app
```

### 选项2: Agent + Hook完整部署

```bash
# 1. 编译Agent和Hook库
cargo build --release
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 2. 创建配置文件
cp agent_only_file.toml /etc/tls_key_agent.toml

# 3. 启动Agent服务
sudo ./target/release/tls_key_agent --config /etc/tls_key_agent.toml --daemon

# 4. 集成到应用
export LD_PRELOAD=/path/to/libtls_agent_hook.so
your_https_application
```

## 📋 Agent配置详解

### 完整配置示例

```toml
# TLS Key Agent 企业级配置
[agent]
name = "enterprise_tls_agent"
version = "0.1.0"
log_level = "info"
buffer_pool_size = 5000
buffer_size = 8192

# 密钥提取配置
[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
capture_session_ticket = false
library_path = "./libtls_agent_hook.so"

# 传输配置
[transport]
enabled_transports = ["File"]  # ["Tcp", "File"] 用于远程传输

# 文件输出配置
[transport.file]
enabled = true
output_path = "/var/log/tls_keys/tls_keys_agent.log"
rotation = true
max_file_size = 104857600  # 100MB
max_files = 10

# TCP传输配置 (可选)
[transport.tcp]
enabled = false
server_host = "collector.company.com"
server_port = 9999
reconnect_interval = 5
max_retries = 10
timeout = 10

# 进程注入配置
[injection]
enabled = false  # 企业环境中通常关闭自动注入
method = "preload"
hook_library = "./libtls_agent_hook.so"
auto_inject = false
skip_critical_processes = true
injection_timeout = 30
max_injected_processes = 1000
process_discovery_interval = 5

# 过滤规则配置
[[filters]]
name = "capture_all"
enabled = true

[[filters]]
name = "https_only"
enabled = false
five_tuple = { dst_port = 443, protocol = "TCP" }

[[filters]]
name = "web_servers"
enabled = false
five_tuple = {}
process_name = "nginx|apache|httpd|lighttpd|caddy"

[[filters]]
name = "exclude_system"
enabled = false
process_name = "systemd|cron|kernel"
```

### 配置字段说明

#### Agent基础配置
- `name`: Agent实例名称
- `version`: 配置文件版本
- `log_level`: 日志级别 (debug/info/warn/error)
- `buffer_pool_size`: 缓冲池大小
- `buffer_size`: 单个缓冲区大小

#### 提取配置
- `enabled`: 是否启用密钥提取
- `capture_client_random`: 提取客户端随机数
- `capture_master_secret`: 提取主密钥
- `capture_session_ticket`: 提取会话票据
- `library_path`: Hook库文件路径

#### 传输配置
- `enabled_transports`: 启用的传输方式列表
- `file`: 文件输出配置
- `tcp`: TCP传输配置

#### 过滤规则
- `name`: 规则名称
- `enabled`: 是否启用规则
- `five_tuple`: 网络五元组过滤
- `process_name`: 进程名过滤 (支持正则表达式)

## 🔧 实际使用场景

### 场景1: 开发者调试

```bash
# 快速调试HTTPS应用
LD_PRELOAD=./libtls_agent_hook.so python3 test_https_app.py
cat /tmp/openssl_keys_all.log

# Wireshark集成
# 设置: Edit → Preferences → Protocols → SSL → Keylog filename
# 路径: /tmp/openssl_keys_all.log
```

### 场景2: Web服务器监控

```bash
# 1. 部署Hook库
sudo cp libtls_agent_hook.so /usr/local/lib/
sudo chmod 644 /usr/local/lib/libtls_agent_hook.so

# 2. 监控Nginx (方式1: 直接Hook)
sudo LD_PRELOAD=/usr/local/lib/libtls_agent_hook.so nginx -c /etc/nginx/nginx.conf

# 3. 监控Nginx (方式2: 环境变量)
echo 'LD_PRELOAD=/usr/local/lib/libtls_agent_hook.so' >> /etc/environment
sudo systemctl restart nginx
```

### 场景3: 企业级部署

```bash
# 1. 安装Agent服务
sudo cp target/release/tls_key_agent /usr/local/bin/
sudo cp agent_only_file.toml /etc/tls_key_agent.toml

# 2. 创建systemd服务
sudo tee /etc/systemd/system/tls-key-agent.service > /dev/null <<EOF
[Unit]
Description=TLS Key Agent
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/bin/tls_key_agent --config /etc/tls_key_agent.toml --daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 3. 启动服务
sudo systemctl daemon-reload
sudo systemctl enable tls-key-agent
sudo systemctl start tls-key-agent

# 4. 部署Hook库到应用服务器
for server in web1 web2 web3; do
    scp libtls_agent_hook.so $server:/usr/local/lib/
    ssh $server "echo 'LD_PRELOAD=/usr/local/lib/libtls_agent_hook.so' >> /etc/environment"
done
```

### 场景4: 安全渗透测试

```bash
# 1. 编译Hook库
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 2. 监控目标应用
LD_PRELOAD=./libtls_agent_hook.so /path/to/target_application

# 3. 实时查看密钥
tail -f /tmp/openssl_keys_all.log

# 4. 集成到Wireshark
# 设置密钥文件路径后，HTTPS流量自动解密
```

## 📊 性能监控

### Agent状态监控

```bash
# 检查Agent进程
ps aux | grep tls_key_agent

# 检查输出文件
ls -la /tmp/tls_keys_agent*.log
tail -f /tmp/tls_keys_agent*.log

# 检查系统资源
top -p $(pgrep tls_key_agent)
```

### 密钥提取统计

```bash
# 统计密钥数量
echo "Client Random数量: $(grep -c '^CLIENT_RANDOM' /tmp/openssl_keys_all.log)"
echo "有效Master Secret: $(grep -v '000000000000' /tmp/openssl_keys_all.log | wc -l)"

# 按时间分布统计
grep '^CLIENT_RANDOM' /tmp/openssl_keys_all.log | cut -d' ' -f4 | sort | uniq -c
```

## 🔍 故障排除

### 常见问题

#### 1. Hook库未生效
```bash
# 检查库文件权限
ls -la libtls_agent_hook.so

# 检查LD_PRELOAD设置
echo $LD_PRELOAD

# 验证库加载
LD_PRELOAD=./libtls_agent_hook.so ldd /bin/ls
```

#### 2. Agent启动失败
```bash
# 检查配置文件语法
./target/release/tls_key_agent --config agent_config.toml --help

# 查看详细错误
./target/release/tls_key_agent --config agent_config.toml 2>&1 | head -20
```

#### 3. 无密钥输出
```bash
# 检查目标应用是否使用TLS
LD_PRELOAD=./libtls_agent_hook.so strace -e connect curl https://example.com

# 检查Hook库日志
export RUST_LOG=debug
LD_PRELOAD=./libtls_agent_hook.so your_app 2>&1 | grep TLS
```

### 调试技巧

```bash
# 1. 启用详细日志
RUST_LOG=debug ./target/release/tls_key_agent --config agent_config.toml

# 2. 检查Hook库加载
LD_PRELOAD=./libtls_agent_hook.so LD_DEBUG=libs curl https://example.com 2>&1 | grep tls_agent

# 3. 验证密钥格式
python3 -c "
import binascii
with open('/tmp/openssl_keys_all.log', 'r') as f:
    for line in f:
        if line.startswith('CLIENT_RANDOM'):
            parts = line.strip().split()
            if len(parts) >= 3:
                client_random = parts[1]
                master_secret = parts[2]
                print(f'Client Random ({len(client_random)} chars): {client_random[:16]}...')
                print(f'Master Secret ({len(master_secret)} chars): {master_secret[:16]}...')
                break
"
```

## 📈 最佳实践

### 1. 生产环境部署
- 使用systemd管理Agent进程
- 配置日志轮转避免磁盘占满
- 设置适当的文件权限和访问控制
- 监控Agent进程健康状态

### 2. 安全考虑
- 限制配置文件访问权限
- 加密网络传输的密钥数据
- 定期清理历史密钥文件
- 审计Agent访问日志

### 3. 性能优化
- 根据负载调整缓冲池大小
- 使用SSD存储密钥日志文件
- 合理设置文件轮转策略
- 监控系统资源使用情况

## 📚 相关文档

- [主动式Hook设计文档](PROACTIVE_HOOK_INDEX.md)
- [使用场景对比分析](../SCENARIO_COMPARISON.md)
- [Agent需求分析](../ANALYSIS_WHEN_AGENT_NEEDED.md)

---

**注意**: 本工具仅用于合法的安全测试和监控目的。请确保在使用前获得适当的授权。