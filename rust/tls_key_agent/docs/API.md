# TLS Key Agent API 文档

## 概述

本文档描述了TLS Key Agent提供的所有API接口，包括C FFI接口、Rust内部API和REST API。TLS Key Agent采用**eBPF内核级架构**，提供了丰富的API来支持系统级TLS密钥的提取、处理和传输。

## 🚀 核心功能（v1.0.0）

### eBPF架构API
- **内核级监控**: 基于eBPF的系统级TLS密钥提取
- **全系统覆盖**: 一次部署监控所有TLS连接
- **零侵入部署**: 无需修改目标应用程序
- **企业级可靠性**: 负载均衡、故障恢复、性能监控
- **多SSL库支持**: OpenSSL、GnuTLS、NSS、BoringSSL、LibreSSL

## 目录

1. [C FFI接口](#c-ffi接口)
2. [Rust内部API](#rust内部api)
3. [REST API](#rest-api)
4. [配置API](#配置api)
5. [错误码](#错误码)
6. [数据类型](#数据类型)

## C FFI接口

### 初始化和生命周期管理

#### `tls_key_agent_init`

初始化TLS Key Agent。

```c
int tls_key_agent_init(const char* config_path);
```

**参数:**
- `config_path`: 配置文件路径，可以为NULL使用默认配置

**返回值:**
- `0`: 成功
- `-1`: 初始化失败
- `-2`: 配置文件错误
- `-3`: 系统资源不足

**示例:**
```c
int result = tls_key_agent_init("/etc/tls_agent/config.toml");
if (result != 0) {
    fprintf(stderr, "初始化失败: %d\n", result);
    return -1;
}
```

#### `tls_key_agent_start`

启动TLS Key Agent服务。

```c
int tls_key_agent_start(void);
```

**返回值:**
- `0`: 成功
- `-1`: Agent未初始化
- `-2`: 服务启动失败

#### `tls_key_agent_stop`

停止TLS Key Agent服务。

```c
int tls_key_agent_stop(void);
```

**返回值:**
- `0`: 成功
- `-1`: Agent未初始化

#### `tls_key_agent_cleanup`

清理TLS Key Agent资源。

```c
int tls_key_agent_cleanup(void);
```

**返回值:**
- `0`: 成功
- `-1`: 清理过程中出现错误

### 密钥事件回调

#### `tls_key_agent_on_client_random`

处理Client Random事件。

```c
int tls_key_agent_on_client_random(
    void* ssl_ptr,
    const uint8_t* client_random,
    size_t len
);
```

**参数:**
- `ssl_ptr`: SSL对象指针
- `client_random`: Client Random数据
- `len`: Client Random长度（应为32字节）

**返回值:**
- `0`: 成功
- `-1`: 参数无效
- `-2`: 处理器未初始化
- `-3`: 内部处理错误

#### `tls_key_agent_on_master_secret`

处理Master Secret事件。

```c
int tls_key_agent_on_master_secret(
    void* ssl_ptr,
    const uint8_t* master_secret,
    size_t len
);
```

**参数:**
- `ssl_ptr`: SSL对象指针
- `master_secret`: Master Secret数据
- `len`: Master Secret长度（应为48字节）

**返回值:**
- `0`: 成功
- `-1`: 参数无效
- `-2`: 处理器未初始化
- `-3`: 内部处理错误

#### `tls_key_agent_on_connection_info`

处理连接信息事件。

```c
int tls_key_agent_on_connection_info(
    void* ssl_ptr,
    const char* src_ip,
    uint16_t src_port,
    const char* dst_ip,
    uint16_t dst_port,
    const char* protocol
);
```

**参数:**
- `ssl_ptr`: SSL对象指针
- `src_ip`: 源IP地址字符串
- `src_port`: 源端口
- `dst_ip`: 目标IP地址字符串
- `dst_port`: 目标端口
- `protocol`: 协议字符串（如"TCP"）

**返回值:**
- `0`: 成功
- `-1`: 参数无效
- `-2`: 处理器未初始化

### 配置管理

#### `tls_key_agent_set_log_level`

设置日志级别。

```c
void tls_key_agent_set_log_level(int level);
```

**参数:**
- `level`: 日志级别
  - `0`: Error
  - `1`: Warn
  - `2`: Info
  - `3`: Debug
  - `4`: Trace

#### `tls_key_agent_add_filter`

动态添加过滤规则。

```c
int tls_key_agent_add_filter(const char* filter_json);
```

**参数:**
- `filter_json`: 过滤规则的JSON字符串

**返回值:**
- `0`: 成功
- `-1`: JSON格式错误
- `-2`: 规则验证失败

**示例:**
```c
const char* filter = "{"
    "\"name\": \"nginx_filter\","
    "\"enabled\": true,"
    "\"process_name\": \"nginx\","
    "\"dst_port\": 443"
"}";

int result = tls_key_agent_add_filter(filter);
```

#### `tls_key_agent_remove_filter`

移除过滤规则。

```c
int tls_key_agent_remove_filter(const char* filter_name);
```

**参数:**
- `filter_name`: 要移除的规则名称

**返回值:**
- `0`: 成功
- `-1`: 规则不存在

### 统计信息

#### `tls_key_agent_get_stats`

获取统计信息。

```c
int tls_key_agent_get_stats(char* stats_json, size_t* len);
```

**参数:**
- `stats_json`: 输出缓冲区，用于存储JSON格式的统计信息
- `len`: 输入时为缓冲区大小，输出时为实际数据长度

**返回值:**
- `0`: 成功
- `-1`: 缓冲区不足
- `-2`: 获取统计信息失败

**示例:**
```c
char buffer[4096];
size_t len = sizeof(buffer);
int result = tls_key_agent_get_stats(buffer, &len);
if (result == 0) {
    printf("统计信息: %s\n", buffer);
}
```

## Rust内部API

### 核心结构体

#### `TlsKeyAgent`

主要的Agent结构体。

```rust
#[derive(Debug, Clone)]
pub struct TlsKeyAgent {
    extractor: Arc<KeyExtractor>,
    transport: Arc<TransportManager>,
}
```

**方法:**

```rust
impl TlsKeyAgent {
    pub fn new(config: AgentConfig) -> Result<Self, TlsKeyAgentError>;
    pub async fn start(&self) -> Result<(), TlsKeyAgentError>;
    pub async fn stop(&self) -> Result<(), TlsKeyAgentError>;
    pub fn get_stats(&self) -> AgentStats;
}
```

#### `KeyExtractor`

密钥提取器。

```rust
pub struct KeyExtractor {
    config: ExtractorConfig,
    key_processor: Arc<KeyProcessor>,
    hooks: Vec<Box<dyn HookInterface>>,
}
```

**方法:**

```rust
impl KeyExtractor {
    pub fn new(config: ExtractorConfig) -> Result<Self, TlsKeyAgentError>;
    pub async fn process_client_random(&self, ssl_ptr: *mut c_void, data: &[u8]) -> Result<(), TlsKeyAgentError>;
    pub async fn process_master_secret(&self, ssl_ptr: *mut c_void, data: &[u8]) -> Result<(), TlsKeyAgentError>;
    pub async fn process_connection_info(&self, ssl_ptr: *mut c_void, info: ConnectionInfo) -> Result<(), TlsKeyAgentError>;
}
```

#### `KeyProcessor`

密钥处理器。

```rust
pub struct KeyProcessor {
    sessions: Arc<RwLock<HashMap<String, TlsSession>>>,
    filter_engine: Arc<FilterEngine>,
    transport_manager: Arc<TransportManager>,
    buffer_pool: Arc<BufferPool>,
}
```

**方法:**

```rust
impl KeyProcessor {
    pub fn new(config: ProcessorConfig) -> Result<Self, TlsKeyAgentError>;
    pub async fn process_client_random(&self, ssl_ptr: *mut c_void, data: Vec<u8>) -> Result<(), TlsKeyAgentError>;
    pub async fn process_master_secret(&self, ssl_ptr: *mut c_void, data: Vec<u8>) -> Result<(), TlsKeyAgentError>;
    pub async fn process_connection_info(&self, ssl_ptr: *mut c_void, info: ConnectionInfo) -> Result<(), TlsKeyAgentError>;
    pub fn get_session_count(&self) -> usize;
    pub fn cleanup_expired_sessions(&self);
}
```

### 传输接口

#### `TransportManager`

传输管理器。

```rust
pub trait Transport: Send + Sync {
    async fn send(&self, message: TransportMessage) -> Result<(), TransportError>;
    async fn flush(&self) -> Result<(), TransportError>;
    fn is_connected(&self) -> bool;
}

pub struct TransportManager {
    transports: Vec<Box<dyn Transport>>,
    fallback_enabled: bool,
}
```

**方法:**

```rust
impl TransportManager {
    pub fn new(config: TransportConfig) -> Result<Self, TlsKeyAgentError>;
    pub async fn add_transport(&mut self, transport: Box<dyn Transport>);
    pub async fn send_message(&self, message: TransportMessage) -> Result<(), TransportError>;
    pub async fn flush_all(&self) -> Result<(), TransportError>;
}
```

### 过滤接口

#### `FilterEngine`

过滤引擎。

```rust
pub struct FilterEngine {
    rules: Arc<RwLock<Vec<FilterRule>>>,
    rule_cache: Arc<Mutex<LruCache<String, bool>>>,
}
```

**方法:**

```rust
impl FilterEngine {
    pub fn new() -> Self;
    pub fn add_rule(&self, rule: FilterRule) -> Result<(), FilterError>;
    pub fn remove_rule(&self, rule_name: &str) -> Result<(), FilterError>;
    pub fn should_process(&self, session: &TlsSession) -> bool;
    pub fn list_rules(&self) -> Vec<FilterRule>;
}
```

## REST API

### 概述

TLS Key Agent提供REST API用于远程配置和监控，默认端口为8080。

### 认证

API使用Bearer Token认证：

```http
Authorization: Bearer <token>
```

### 端点

#### 获取Agent状态

```http
GET /api/v1/status
```

**响应:**
```json
{
  "status": "running",
  "version": "0.1.0",
  "uptime": 3600,
  "session_count": 150,
  "last_activity": "2023-11-04T12:34:56Z"
}
```

#### 获取统计信息

```http
GET /api/v1/stats
```

**响应:**
```json
{
  "total_sessions": 1500,
  "active_sessions": 150,
  "processed_keys": 1450,
  "failed_sessions": 50,
  "transport_stats": {
    "tcp": {
      "sent_messages": 1400,
      "failed_messages": 10,
      "connection_count": 3
    },
    "file": {
      "written_files": 50,
      "total_bytes": 1048576
    }
  }
}
```

#### 获取过滤规则

```http
GET /api/v1/filters
```

**响应:**
```json
{
  "filters": [
    {
      "name": "nginx_https",
      "enabled": true,
      "priority": 100,
      "process_name": "nginx",
      "dst_port": 443,
      "match_count": 1200
    }
  ]
}
```

#### 添加过滤规则

```http
POST /api/v1/filters
Content-Type: application/json

{
  "name": "apache_filter",
  "enabled": true,
  "priority": 200,
  "process_name": "apache2",
  "dst_port": 443,
  "src_ip_range": "192.168.1.0/24"
}
```

**响应:**
```json
{
  "success": true,
  "message": "过滤规则添加成功",
  "rule_id": "apache_filter"
}
```

#### 更新过滤规则

```http
PUT /api/v1/filters/{rule_name}
Content-Type: application/json

{
  "enabled": false
}
```

**响应:**
```json
{
  "success": true,
  "message": "过滤规则更新成功"
}
```

#### 删除过滤规则

```http
DELETE /api/v1/filters/{rule_name}
```

**响应:**
```json
{
  "success": true,
  "message": "过滤规则删除成功"
}
```

#### 获取配置

```http
GET /api/v1/config
```

**响应:**
```json
{
  "agent": {
    "name": "tls_key_agent",
    "log_level": "info",
    "buffer_pool_size": 1000
  },
  "extraction": {
    "enabled": true,
    "capture_client_random": true,
    "capture_master_secret": true
  },
  "transport": {
    "enabled_transports": ["Tcp", "File"],
    "tcp": {
      "server_host": "127.0.0.1",
      "server_port": 9999
    }
  }
}
```

#### 更新配置

```http
PUT /api/v1/config
Content-Type: application/json

{
  "agent": {
    "log_level": "debug"
  }
}
```

**响应:**
```json
{
  "success": true,
  "message": "配置更新成功",
  "restart_required": false
}
```

#### 重启Agent

```http
POST /api/v1/restart
```

**响应:**
```json
{
  "success": true,
  "message": "Agent重启成功"
}
```

## 配置API

### 配置文件格式

#### TOML格式

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
enabled_transports = ["Tcp", "File"]

[transport.tcp]
enabled = true
server_host = "127.0.0.1"
server_port = 9999
reconnect_interval = 5
timeout = 30

[transport.file]
enabled = true
directory = "/var/log/tls_agent"
filename_pattern = "tls_keys_{timestamp}.log"
max_file_size = "100MB"
max_files = 10

[[filters]]
name = "nginx_https"
enabled = true
priority = 100
process_name = "nginx"
five_tuple = { dst_port = 443 }

[[filters]]
name = "internal_network"
enabled = true
priority = 200
five_tuple = {
    src_ip = "192.168.0.0/16",
    dst_port = [443, 8443]
}
```

#### JSON格式

```json
{
  "agent": {
    "name": "tls_key_agent",
    "log_level": "info",
    "buffer_pool_size": 1000,
    "buffer_size": 8192
  },
  "extraction": {
    "enabled": true,
    "capture_client_random": true,
    "capture_master_secret": true,
    "library_path": "./target/release/libtls_key_agent.so"
  },
  "transport": {
    "enabled_transports": ["Tcp", "File"],
    "tcp": {
      "enabled": true,
      "server_host": "127.0.0.1",
      "server_port": 9999,
      "reconnect_interval": 5,
      "timeout": 30
    },
    "file": {
      "enabled": true,
      "directory": "/var/log/tls_agent",
      "filename_pattern": "tls_keys_{timestamp}.log",
      "max_file_size": "100MB",
      "max_files": 10
    }
  },
  "filters": [
    {
      "name": "nginx_https",
      "enabled": true,
      "priority": 100,
      "process_name": "nginx",
      "five_tuple": {
        "dst_port": 443
      }
    }
  ]
}
```

## 错误码

### C FFI错误码

| 错误码 | 含义 | 描述 |
|--------|------|------|
| 0 | Success | 操作成功 |
| -1 | InvalidInput | 输入参数无效 |
| -2 | NotInitialized | 组件未初始化 |
| -3 | InternalError | 内部处理错误 |
| -4 | MemoryError | 内存分配失败 |
| -5 | NetworkError | 网络连接错误 |
| -6 | ConfigError | 配置错误 |
| -7 | PermissionDenied | 权限不足 |

### HTTP状态码

| 状态码 | 含义 | 描述 |
|--------|------|------|
| 200 | OK | 请求成功 |
| 400 | Bad Request | 请求格式错误 |
| 401 | Unauthorized | 认证失败 |
| 403 | Forbidden | 权限不足 |
| 404 | Not Found | 资源不存在 |
| 409 | Conflict | 资源冲突 |
| 500 | Internal Server Error | 服务器内部错误 |

## 数据类型

### TlsSession

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSession {
    pub session_id: String,
    pub client_random: Option<Vec<u8>>,
    pub master_secret: Option<Vec<u8>>,
    pub five_tuple: FiveTuple,
    pub process_info: ProcessInfo,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}
```

### FiveTuple

```rust
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}
```

### ProcessInfo

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub process_name: String,
    pub command_line: String,
    pub exe_path: String,
    pub cwd: String,
}
```

### TransportMessage

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct TransportMessage {
    pub message_type: MessageType,
    pub timestamp: SystemTime,
    pub session: TlsSession,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageType {
    TlsKey,
    SessionStart,
    SessionEnd,
    Heartbeat,
}
```

### FilterRule

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    pub name: String,
    pub enabled: bool,
    pub priority: u32,
    pub five_tuple: Option<FiveTupleFilter>,
    pub process_name: Option<StringFilter>,
    pub pid: Option<NumericFilter>,
    pub time_range: Option<TimeRangeFilter>,
    pub custom_fields: HashMap<String, Value>,
}
```

## 使用示例

### C语言示例

```c
#include <stdio.h>
#include <stdlib.h>
#include "tls_key_agent.h"

int main() {
    // 初始化Agent
    if (tls_key_agent_init("config.toml") != 0) {
        fprintf(stderr, "初始化失败\n");
        return -1;
    }

    // 启动Agent
    if (tls_key_agent_start() != 0) {
        fprintf(stderr, "启动失败\n");
        return -1;
    }

    // 设置日志级别
    tls_key_agent_set_log_level(2); // Info级别

    // 添加过滤规则
    const char* filter = "{"
        "\"name\": \"test_filter\","
        "\"enabled\": true,"
        "\"process_name\": \"nginx\""
    "}";
    tls_key_agent_add_filter(filter);

    // 运行一段时间
    sleep(60);

    // 获取统计信息
    char stats[4096];
    size_t len = sizeof(stats);
    if (tls_key_agent_get_stats(stats, &len) == 0) {
        printf("统计信息: %s\n", stats);
    }

    // 清理
    tls_key_agent_stop();
    tls_key_agent_cleanup();

    return 0;
}
```

### Rust语言示例

```rust
use tls_key_agent::{TlsKeyAgent, AgentConfig};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 加载配置
    let config = AgentConfig::from_file("config.toml")?;

    // 创建Agent
    let agent = TlsKeyAgent::new(config)?;

    // 启动Agent
    agent.start().await?;

    // 运行一段时间
    tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

    // 获取统计信息
    let stats = agent.get_stats();
    println!("统计信息: {:?}", stats);

    // 停止Agent
    agent.stop().await?;

    Ok(())
}
```

### REST API示例

```bash
# 获取Agent状态
curl -H "Authorization: Bearer <token>" \
     http://localhost:8080/api/v1/status

# 添加过滤规则
curl -X POST \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "test_filter",
       "enabled": true,
       "process_name": "nginx"
     }' \
     http://localhost:8080/api/v1/filters

# 获取统计信息
curl -H "Authorization: Bearer <token>" \
     http://localhost:8080/api/v1/stats
```

## 版本更新历史

### v1.0.0 (2025-12-01) - eBPF架构升级

**API变更：**
- ✅ **架构升级**: 从主动式Hook升级到eBPF内核级监控
- ✅ **系统级API**: 支持全系统TLS连接监控
- ✅ **零依赖部署**: 无需LD_PRELOAD配置
- ✅ **企业级功能**: 负载均衡、故障恢复、性能监控API

**新增API：**
- eBPF程序加载和管理API
- 系统级进程过滤API
- UDP批量传输配置API
- 企业级监控和告警API

**废弃API：**
- LD_PRELOAD相关的Hook API
- 进程级密钥提取API
- 单进程配置API

### v0.2.0 (2025-11-05) - 主动式Hook重构

### v0.1.0 (2023-11-04) - 初始版本

---

*API文档版本: v1.0.0*
*最后更新: 2025-12-01*