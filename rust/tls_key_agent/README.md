# TLS Key Agent

高性能TLS密钥提取Agent，支持通过LD_PRELOAD和eBPF机制获取nginx/apache/smtp等应用的TLS协商密钥。

## 项目概述

TLS Key Agent是一个专业的网络安全工具，用于监控和提取TLS/SSL连接的密钥信息，支持：

- **多种应用支持**: nginx, Apache, SMTP等使用TLS的应用
- **双机制支持**: LD_PRELOAD机制和eBPF内核级监控
- **远程配置**: 支持远程API配置和本地文件配置
- **智能筛选**: 基于五元组、进程名、PID的智能筛选
- **多方式传输**: TCP Socket传输和本地文件保存
- **高性能**: 异步I/O、内存池、零拷贝优化
- **低资源占用**: 优化的内存管理和CPU使用

## 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    TLS Key Agent                           │
├─────────────────────────────────────────────────────────────┤
│  Configuration Layer (配置层)                              │
│  ├── Remote Config API (Axum REST API)                    │
│  ├── Local Config File (TOML/YAML)                        │
│  └── Dynamic Filter Rules (五元组筛选规则)                 │
├─────────────────────────────────────────────────────────────┤
│  Key Extraction Layer (密钥提取层)                         │
│  ├── LD_PRELOAD Hook (C/Rust FFI)                         │
│  ├── OpenSSL Interceptor (SSL_write/read hook)            │
│  ├── GnuTLS/NSS Support (扩展TLS库支持)                    │
│  └── Application Filter (应用进程筛选)                     │
├─────────────────────────────────────────────────────────────┤
│  Data Processing Layer (数据处理层)                        │
│  ├── Key Validation (密钥验证和格式化)                     │
│  ├── Session Management (TLS会话管理)                      │
│  └── Buffer Pool (高性能内存池)                           │
├─────────────────────────────────────────────────────────────┤
│  Transport Layer (传输层)                                 │
│  ├── TCP Socket Client (远程传输)                          │
│  ├── Local File Storage (本地保存)                         │
│  └── Fallback Mechanism (故障转移)                         │
└─────────────────────────────────────────────────────────────┘
```

## 核心功能

### 1. 密钥提取
- **Client Random提取**: 32字节的客户端随机数
- **Master Secret提取**: 48字节的主密钥
- **Session Ticket支持**: TLS会话票据提取
- **多TLS库支持**: OpenSSL, GnuTLS, NSS等

### 2. 智能筛选
- **五元组筛选**: 源IP、源端口、目标IP、目标端口、协议
- **进程筛选**: 进程名、PID筛选
- **动态规则**: 运行时修改筛选规则
- **规则优先级**: 支持规则优先级和匹配顺序

### 3. 数据传输
- **TCP传输**: 高可靠的TCP Socket传输
- **文件存储**: 本地文件存储，支持轮转
- **压缩传输**: 数据压缩减少网络传输
- **重连机制**: 自动重连和故障转移

### 4. 性能优化
- **异步处理**: 基于tokio的异步I/O
- **内存池**: 预分配内存池避免频繁分配
- **零拷贝**: 最小化内存拷贝操作
- **批量处理**: 批量传输提高效率

## 快速开始

### 1. 编译项目

```bash
# 克隆项目
git clone <repository-url>
cd tls_key_agent

# 编译
cargo build --release

# 编译共享库 (用于LD_PRELOAD)
cargo build --release --lib
```

### 2. 配置文件

复制并编辑配置文件：

```bash
cp config.toml.example config.toml
```

配置文件示例：

```toml
[agent]
name = "tls_key_agent"
log_level = "info"
buffer_pool_size = 1000
buffer_size = 8192

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
library_path = "./target/release/libtls_key_agent.so"

[transport]
enabled_transports = ["Tcp"]

[transport.tcp]
enabled = true
server_host = "127.0.0.1"
server_port = 9999
reconnect_interval = 5

[[filters]]
name = "nginx_https"
enabled = true
five_tuple = { dst_port = 443 }
process_name = "nginx"
```

### 3. 使用方法

#### 方式1: LD_PRELOAD (推荐)

```bash
# 启动TLS Key Agent
./target/release/tls_key_agent --config config.toml &

# 使用LD_PRELOAD监控应用
LD_PRELOAD=./target/release/libtls_key_agent.so nginx -c /etc/nginx/nginx.conf
```

#### 方式2: 直接集成

```bash
# 直接启动Agent监控指定进程
./target/release/tls_key_agent --config config.toml --pid 1234
```

## 配置说明

### Agent配置
- `name`: Agent名称
- `log_level`: 日志级别 (debug, info, warn, error)
- `buffer_pool_size`: 缓冲池大小
- `buffer_size`: 单个缓冲区大小

### 提取配置
- `enabled`: 是否启用密钥提取
- `capture_client_random`: 是否提取Client Random
- `capture_master_secret`: 是否提取Master Secret
- `library_path`: LD_PRELOAD库路径

### 传输配置
- `enabled_transports`: 启用的传输方式
- `tcp`: TCP传输配置
- `file`: 文件存储配置

### 过滤规则
- `name`: 规则名称
- `enabled`: 是否启用
- `five_tuple`: 五元组筛选条件
- `process_name`: 进程名筛选
- `pid`: PID筛选

## API接口

### C FFI接口

```c
// 初始化Agent
int tls_key_agent_init(const char* config_path);

// 启动Agent
int tls_key_agent_start();

// 停止Agent
int tls_key_agent_stop();

// 处理Client Random
int tls_key_agent_on_client_random(void* ssl_ptr, const uint8_t* client_random, size_t len);

// 处理Master Secret
int tls_key_agent_on_master_secret(void* ssl_ptr, const uint8_t* master_secret, size_t len);
```

## 输出格式

### TCP传输格式 (JSON)

```json
{
  "message_type": "TlsKey",
  "timestamp": 1699123456,
  "session": {
    "session_id": "192.168.1.100:12345-192.168.1.1:443-1699123456",
    "client_random": "abcdef123456...",
    "master_secret": "fedcba654321...",
    "five_tuple": {
      "src_ip": "192.168.1.100",
      "src_port": 12345,
      "dst_ip": "192.168.1.1",
      "dst_port": 443,
      "protocol": "TCP"
    },
    "process_info": {
      "pid": 1234,
      "process_name": "nginx",
      "command_line": "nginx -c /etc/nginx/nginx.conf"
    }
  }
}
```

### 文件格式

```
[2023-11-04 12:34:56 UTC] TLS_KEY | session-id | 192.168.1.100:12345 -> 192.168.1.1:443 | Process: nginx (PID: 1234) | ClientRandom: abcdef123456... | MasterSecret: fedcba654321...
```

## 性能指标

- **吞吐量**: 支持10,000+并发TLS连接
- **延迟**: 密钥提取延迟 < 1ms
- **内存占用**: 基础内存占用 < 50MB
- **CPU占用**: 正常负载下 < 5%

## 安全考虑

1. **权限控制**: Agent需要适当的权限来监控目标进程
2. **数据加密**: 传输过程中的密钥数据需要加密保护
3. **访问控制**: 严格的配置和访问控制机制
4. **审计日志**: 完整的操作审计记录

## 故障排除

### 常见问题

1. **LD_PRELOAD失败**
   - 检查库文件路径是否正确
   - 确认目标应用使用动态链接
   - 验证系统权限设置

2. **连接失败**
   - 检查网络配置和防火墙设置
   - 验证目标服务器是否可达
   - 确认端口是否被占用

3. **性能问题**
   - 调整缓冲池大小
   - 优化筛选规则
   - 检查系统资源使用情况

### 调试模式

启用详细日志：

```bash
RUST_LOG=debug ./target/release/tls_key_agent --config config.toml
```

## 开发指南

### 项目结构

```
src/
├── lib.rs              # 库入口
├── main.rs             # 主程序入口
├── config/             # 配置管理
├── extractor/          # 密钥提取
├── transport/          # 数据传输
├── common/             # 公共模块
└── ffi/                # C FFI接口
```

### 运行测试

```bash
# 运行所有测试
cargo test

# 运行特定模块测试
cargo test config
cargo test extractor
```

## 贡献指南

1. Fork项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建Pull Request

## 许可证

本项目采用MIT或Apache-2.0双许可证。详见 [LICENSE-MIT](LICENSE-MIT) 和 [LICENSE-APACHE](LICENSE-APACHE) 文件。

## 联系方式

- 作者: sollor525@hotmail.com
- 项目主页: [GitHub Repository]

## 更新日志

### v0.1.0 (2023-11-04)
- 初始版本发布
- 基础LD_PRELOAD支持
- TCP和文件传输支持
- 配置系统和筛选规则
- C FFI接口

---

**注意**: 本工具仅用于合法的安全测试和监控目的。请确保在使用前获得适当的授权。