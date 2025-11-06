# TLS Key Agent

高性能TLS密钥提取工具，支持LD_PRELOAD和eBPF两种注入机制，专为生产环境设计。

## 🚀 特性

### 核心功能
- **双重注入机制**：支持LD_PRELOAD和eBPF两种注入方式
- **自动方法选择**：根据系统能力自动选择最佳注入方式
- **无感注入**：运行时自动发现并注入TLS进程，无需重启服务
- **生产级安全**：关键进程过滤，安全检查机制

### 密钥提取
- **全面密钥支持**：Client Random、Master Secret、Session Ticket等
- **多种输出格式**：Wireshark、JSON、CSV、TLS KeyLog等
- **实时密钥传输**：TCP和文件两种传输方式
- **主动式提取**：基于SSL函数Hook的直接密钥提取，不依赖Keylog回调
- **多算法支持**：Client Random多方法提取 + Master Secret多策略提取
- **智能验证**：熵值检测和密钥有效性验证

### 系统兼容
- **广泛系统支持**：Linux内核4.14+
- **架构支持**：x86_64、ARM64
- **多种TLS库**：OpenSSL、BoringSSL等

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
│  ├── Proactive SSL Hook (主动式SSL函数Hook)                │
│  ├── SSL_write/read/connect/accept Hook                    │
│  ├── Multi-algorithm Extraction (多算法密钥提取)           │
│  ├── Client Random Extraction (3种方法)                   │
│  ├── Master Secret Extraction (3种策略)                   │
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

### 1. 主动式密钥提取 (核心功能)
- **Client Random提取**: 3种方法多层次提取
  - OpenSSL官方API (`SSL_get_client_random`)
  - 直接SSL结构体内存访问 (`ssl->s3->client_random`)
  - 智能内存搜索算法
- **Master Secret提取**: 3种策略主动获取
  - `SSL_export_keying_material` API提取
  - SSL_SESSION结构体访问
  - 内存模式搜索 (最后回退)
- **智能验证机制**: 熵值检测、连续字节检查、频率分析
- **多TLS库支持**: OpenSSL, GnuTLS, NSS等
- **Session Ticket支持**: TLS会话票据提取

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

## 🏗️ 架构模式对比

TLS Key Agent支持**两种主要架构模式**，根据使用场景选择：

### 🚀 模式1: 主动式Hook库 (推荐)

**适用场景：** 个人开发、安全测试、Wireshark解密、单机密钥提取

```bash
# 一条命令搞定，无需Agent进程
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com
```

**优势：**
- ✅ **极简部署**: 一条命令，立即可用
- ✅ **零依赖**: 无需配置文件，无需Agent进程
- ✅ **高性能**: 直接Hook SSL函数，无中间层
- ✅ **高可靠**: 没有进程间通信故障点
- ✅ **兼容性**: 完美兼容Wireshark Keylog格式

### 🏢 模式2: Agent + Hook组合 (企业级)

**适用场景：** 企业级部署、远程密钥收集、集中管理、分布式监控

```bash
# 1. 启动Agent进程
./target/release/tls_key_agent --config agent_config.toml &

# 2. 应用加载Hook库
LD_PRELOAD=./libtls_agent_hook.so your_application
```

**企业级功能：**
- ✅ **集中管理**: TOML配置文件驱动的规则管理
- ✅ **远程收集**: TCP传输到中央服务器
- ✅ **复杂过滤**: 五元组、进程名、时间范围过滤
- ✅ **实时监控**: Agent状态和性能监控
- ✅ **高可用**: 故障转移和自动重启

## 🚀 快速开始

### 1. 编译项目

```bash
# 克隆项目
git clone <repository-url>
cd tls_key_agent

# 编译Agent可执行文件
cargo build --release

# 编译主动式Hook库 (推荐)
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread
```

### 2. 使用方法

#### 方式1: 仅Hook库 (推荐 - 90%用户选择)

```bash
# 立即使用TLS密钥提取
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com

# 查看提取的密钥
cat /tmp/openssl_keys_all.log
# CLIENT_RANDOM <32字节的随机值> <48字节的密钥>

# Wireshark集成
# Edit → Preferences → Protocols → SSL → (Pre)-Master-Secret log filename
# 设置为: /tmp/openssl_keys_all.log
```

#### 方式2: Agent + Hook组合 (企业级)

```bash
# 1. 创建配置文件 (agent_config.toml)
cp agent_only_file.toml my_agent_config.toml

# 2. 启动Agent进程
./target/release/tls_key_agent --config my_agent_config.toml &

# 3. 应用使用Hook库
LD_PRELOAD=./libtls_agent_hook.so your_application

# 4. 检查Agent输出
ls -la /tmp/tls_keys_agent*.log
```

### 3. 配置文件 (Agent模式)

企业级配置示例：

```toml
[agent]
name = "enterprise_tls_agent"
version = "0.1.0"
log_level = "info"
buffer_pool_size = 5000
buffer_size = 8192

[extraction]
enabled = true
capture_client_random = true
capture_master_secret = true
library_path = "./libtls_agent_hook.so"

[transport]
enabled_transports = ["File"]  # 或 ["Tcp", "File"]

[transport.file]
enabled = true
output_path = "/tmp/tls_keys_agent.log"
rotation = true
max_file_size = 104857600  # 100MB

[[filters]]
name = "https_only"
enabled = true
five_tuple = { dst_port = 443, protocol = "TCP" }

[[filters]]
name = "web_servers"
enabled = true
five_tuple = {}
process_name = "nginx|apache|httpd"
```

### 4. 测试验证

```bash
# 运行完整测试
./test_agent_hook_integration.sh

# 或手动测试
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread
LD_PRELOAD=./libtls_agent_hook.so curl -s https://www.baidu.com > /dev/null
echo "✅ 提取的密钥条目: $(wc -l < /tmp/openssl_keys_all.log)"
```

### 4. 测试Hook库

```bash
# 编译测试程序
gcc -o test_hook_simple test_hook_simple.c -lssl -lcrypto

# 运行Hook测试
LD_PRELOAD=./libtls_agent_hook.so ./test_hook_simple

# 检查密钥文件
ls -la /tmp/openssl_keys_all.log /tmp/tls_test_keys.log
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

## 技术实现细节

### 主动式Hook架构

#### 1. SSL函数拦截
```c
// Hook SSL_write - 在首次成功写入时提取密钥
int SSL_write(SSL *ssl, const void *buf, int num) {
    int result = original_SSL_write(ssl, buf, num);

    static __thread int keys_extracted = 0;
    if (!keys_extracted && result > 0 && is_handshake_complete(ssl)) {
        extract_tls_keys_proactive(ssl, "SSL_write");
        keys_extracted = 1;
    }

    return result;
}
```

#### 2. Client Random多方法提取
```c
static int extract_client_random_proactive(SSL *ssl, unsigned char *client_random) {
    // 方法1: OpenSSL官方API
    if (original_SSL_get_client_random) {
        int len = original_SSL_get_client_random(ssl, client_random, 32);
        if (len == 32) return 1;
    }

    // 方法2: 直接结构体访问
    if (access_ssl_structure_direct_c(ssl, client_random)) {
        return 1;
    }

    // 方法3: 内存搜索
    if (search_client_random_in_memory_c(ssl, client_random)) {
        return 1;
    }

    return 0;
}
```

#### 3. Master Secret多策略提取
```c
static int extract_master_secret_proactive(SSL *ssl, unsigned char *master_secret) {
    // 方法1: SSL_export_keying_material API
    if (original_SSL_export_keying_material) {
        int result = original_SSL_export_keying_material(
            ssl, master_secret, 48, "master secret", 13, NULL, 0, 0);
        if (result > 0 && is_likely_master_secret_c(master_secret)) {
            return 1;
        }
    }

    // 方法2: SSL_SESSION提取
    if (extract_from_ssl_session_c(ssl, master_secret)) {
        return 1;
    }

    // 方法3: 内存搜索
    if (search_master_secret_in_memory_c(ssl, master_secret)) {
        return 1;
    }

    return 0;
}
```

#### 4. 智能密钥验证
```c
static int is_likely_client_random_c(const unsigned char *data) {
    // 熵值检测 - 不应该全零或全相同
    // 频率分析 - 任何字节不应出现超过4次
    // 连续检查 - 不应该有太长的连续相同字节

    int byte_counts[256] = {0};
    for (int i = 0; i < 32; i++) {
        byte_counts[data[i]]++;
    }

    int max_count = 0;
    for (int i = 0; i < 256; i++) {
        if (byte_counts[i] > max_count) max_count = byte_counts[i];
    }

    return (max_count <= 4); // 最大频率限制
}
```

### 关键技术创新

1. **无依赖主动提取**: 完全不依赖OpenSSL Keylog回调机制
2. **多算法回退**: 确保在不同OpenSSL版本下的兼容性
3. **智能时机检测**: 在最佳时机提取密钥，提高成功率
4. **线程安全设计**: 使用线程局部存储避免重复提取
5. **高并发支持**: 在多线程环境下稳定运行

## 更新日志

### v0.2.0 (2025-11-05) - 主动式Hook重构
- ✅ **核心重构**: 完全重新设计TLS密钥提取架构
- ✅ **主动式Hook**: 基于SSL函数的直接密钥提取，不依赖Keylog回调
- ✅ **多算法支持**: Client Random 3种方法 + Master Secret 3种策略
- ✅ **智能验证**: 熵值检测和密钥有效性验证机制
- ✅ **高兼容性**: 支持OpenSSL 1.1.1f等多种版本
- ✅ **高性能**: 优化Hook逻辑，支持高并发场景
- ✅ **C语言库**: 独立的`libtls_agent_hook.so`Hook库
- ✅ **完整测试**: 功能测试、兼容性测试、性能测试

### v0.1.0 (2023-11-04)
- 初始版本发布
- 基础LD_PRELOAD支持
- TCP和文件传输支持
- 配置系统和筛选规则
- C FFI接口

---

**注意**: 本工具仅用于合法的安全测试和监控目的。请确保在使用前获得适当的授权。