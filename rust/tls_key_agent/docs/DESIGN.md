# TLS Key Agent 设计文档

## 概述

TLS Key Agent 是一个高性能的TLS密钥提取代理，专门设计用于监控和提取TLS/SSL连接中的密钥材料。本文档详细描述了系统的架构设计、技术选型和实现细节。

## 系统架构

### 整体架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        应用层                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐            │
│  │    Nginx    │  │    Apache   │  │   Postfix   │            │
│  └─────────────┘  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Hook层                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │            LD_PRELOAD Hook (C语言)                         │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │ │
│  │  │SSL_write()  │  │ SSL_read()  │  │SSL_connect()│        │ │
│  │  │    Hook     │  │    Hook     │  │    Hook     │        │ │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FFI接口层                                   │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              C/Rust FFI Bridge                              │ │
│  │  • tls_key_agent_on_client_random()                        │ │
│  │  • tls_key_agent_on_master_secret()                        │ │
│  │  • tls_key_agent_on_connection_info()                      │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   核心处理层 (Rust)                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   配置管理      │  │   密钥提取器    │  │   数据处理器    │ │
│  │ Configuration  │  │  KeyExtractor   │  │  KeyProcessor   │ │
│  │     Manager     │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│                              │                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   过滤引擎      │  │   会话管理      │  │   缓冲池管理    │ │
│  │ Filter Engine   │  │Session Manager  │  │ Buffer Pool     │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     传输层                                     │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   TCP传输       │  │   文件存储      │  │   错误处理      │ │
│  │TCP Transport    │  │File Transport   │  │Error Handler    │ │
│  │                 │  │                 │  │                 │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 核心组件设计

### 1. LD_PRELOAD Hook (openssl_hook.c)

#### 设计目标
- 无侵入性地拦截OpenSSL函数调用
- 提取TLS握手过程中的关键密钥材料
- 获取连接和进程上下文信息

#### 核心机制
```c
// 函数指针声明
static int (*original_SSL_write)(SSL *ssl, const void *buf, int num) = NULL;
static int (*original_SSL_read)(SSL *ssl, void *buf, int num) = NULL;
static int (*original_SSL_connect)(SSL *ssl) = NULL;

// 构造函数自动初始化
__attribute__((constructor))
static void init_openssl_hook(void) {
    // 获取原始函数指针
    original_SSL_write = dlsym(RTLD_NEXT, "SSL_write");
    original_SSL_read = dlsym(RTLD_NEXT, "SSL_read");
    // ... 其他函数
}
```

#### 密钥提取流程
1. **握手检测**: 监控SSL_connect/SSL_accept的返回值
2. **Client Random提取**: 通过SSL_get_client_random API
3. **Master Secret提取**: 多种方法组合提取
4. **上下文信息**: 获取文件描述符对应的网络连接信息

### 2. FFI接口层 (ffi/mod.rs)

#### 设计原则
- 提供稳定的C接口
- 异常安全的跨语言调用
- 高效的数据传递

#### 核心接口
```rust
#[no_mangle]
pub extern "C" fn tls_key_agent_on_client_random(
    ssl_ptr: *mut c_void,
    client_random: *const u8,
    len: usize,
) -> FfiResult {
    // 安全性检查
    if client_random.is_null() || len != 32 {
        return FfiResult::InvalidInput;
    }

    // 转换为Rust类型并处理
    let data = unsafe {
        std::slice::from_raw_parts(client_random, len)
    };

    // 调用核心处理逻辑
    if let Some(processor) = get_global_key_processor() {
        // 异步处理密钥数据
        rt.block_on(processor.process_client_random(ssl_ptr, data));
        FfiResult::Success
    } else {
        FfiResult::NotInitialized
    }
}
```

### 3. 密钥提取器 (extractor/mod.rs)

#### 架构设计
```rust
pub struct KeyExtractor {
    config: ExtractorConfig,
    key_processor: Arc<KeyProcessor>,
    error_handler: Arc<ErrorHandler>,
    hooks: Vec<Box<dyn HookInterface>>,
}
```

#### 核心功能
- **Hook管理**: 加载和管理多个Hook库
- **数据验证**: 验证提取的密钥数据格式
- **事件分发**: 将密钥事件分发给处理器

### 4. 密钥处理器 (extractor/key_processor.rs)

#### 会话管理
```rust
pub struct KeyProcessor {
    sessions: Arc<RwLock<HashMap<String, TlsSession>>>,
    filter_engine: Arc<FilterEngine>,
    transport_manager: Arc<TransportManager>,
    buffer_pool: Arc<BufferPool>,
}
```

#### 处理流程
1. **会话识别**: 基于五元组生成唯一会话ID
2. **数据组装**: 将分散的密钥信息组装成完整会话
3. **规则过滤**: 应用用户定义的过滤规则
4. **数据传输**: 通过传输层发送密钥数据

### 5. 过滤引擎 (config/filter.rs)

#### 过滤规则设计
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
}
```

#### 匹配算法
1. **规则排序**: 按优先级排序规则
2. **快速匹配**: 使用索引优化匹配性能
3. **短路评估**: 遇到匹配规则立即返回

### 6. 传输层 (transport/)

#### TCP传输设计
```rust
pub struct TcpTransport {
    config: TcpConfig,
    connection_pool: Arc<Mutex<Vec<TcpConnection>>>,
    reconnect_scheduler: Arc<ReconnectScheduler>,
}
```

#### 特性
- **连接池**: 复用TCP连接提高性能
- **自动重连**: 指数退避重连策略
- **流量控制**: 防止网络拥塞

## 数据结构设计

### TLS会话结构
```rust
#[derive(Debug, Clone)]
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

### 五元组结构
```rust
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}
```

### 传输消息格式
```rust
#[derive(Debug, Serialize)]
pub struct TransportMessage {
    pub message_type: MessageType,
    pub timestamp: SystemTime,
    pub session: TlsSession,
}
```

## 性能优化策略

### 1. 内存管理
- **对象池**: 预分配常用对象避免频繁创建
- **零拷贝**: 尽可能避免内存拷贝操作
- **内存映射**: 大文件使用内存映射提高I/O性能

### 2. 并发处理
- **异步I/O**: 基于tokio的高性能异步运行时
- **无锁数据结构**: 减少锁竞争提高并发性能
- **工作窃取**: 使用work-stealing调度算法

### 3. 网络优化
- **批量传输**: 聚合多个消息减少网络调用
- **压缩传输**: 使用压缩算法减少带宽占用
- **连接复用**: 复用TCP连接减少握手开销

## 安全设计

### 1. 权限控制
```rust
#[derive(Debug)]
pub struct SecurityConfig {
    pub allowed_users: Vec<String>,
    pub allowed_groups: Vec<String>,
    pub require_root: bool,
    pub max_sessions_per_process: u32,
}
```

### 2. 数据保护
- **传输加密**: 支持TLS加密传输
- **存储加密**: 敏感数据加密存储
- **访问控制**: 基于角色的访问控制

### 3. 审计日志
```rust
pub struct AuditLogger {
    log_file: Arc<Mutex<File>>,
    log_level: LogLevel,
    retention_days: u32,
}
```

## 错误处理策略

### 错误分类
```rust
#[derive(Debug, thiserror::Error)]
pub enum TlsKeyAgentError {
    #[error("配置错误: {0}")]
    Config(String),

    #[error("网络错误: {0}")]
    Network(#[from] std::io::Error),

    #[error("Hook错误: {0}")]
    Hook(String),

    #[error("传输错误: {0}")]
    Transport(String),
}
```

### 恢复策略
1. **自动重试**: 网络错误自动重试
2. **降级服务**: 部分功能失败时提供降级服务
3. **快速失败**: 严重错误时快速失败避免数据损坏

## 测试策略

### 1. 单元测试
- 每个模块独立测试
- Mock外部依赖
- 覆盖率要求 > 90%

### 2. 集成测试
- 端到端功能测试
- 性能基准测试
- 压力测试

### 3. 兼容性测试
- 不同操作系统版本
- 不同OpenSSL版本
- 不同应用场景

## 部署架构

### 单机部署
```
[应用进程] --LD_PRELOAD--> [TLS Key Agent] --TCP--> [密钥收集服务器]
```

### 集群部署
```
[应用进程1] \
[应用进程2] --LD_PRELOAD--> [TLS Key Agent集群] --负载均衡--> [密钥收集集群]
[应用进程N] /
```

## 监控指标

### 性能指标
- **吞吐量**: 每秒处理的TLS连接数
- **延迟**: 密钥提取到传输的延迟
- **资源使用**: CPU、内存、网络使用率

### 业务指标
- **成功率**: 密钥提取成功的百分比
- **错误率**: 各类错误的发生频率
- **会话统计**: 活跃会话数量和趋势

## 未来扩展

### 1. 支持更多TLS库
- GnuTLS
- NSS
- BoringSSL

### 2. 内核级监控
- eBPF程序
- tracepoints
- kprobes

### 3. 云原生支持
- Kubernetes集成
- 服务网格集成
- 容器化部署

---

*设计文档版本: v0.1.0*
*最后更新: 2023-11-04*