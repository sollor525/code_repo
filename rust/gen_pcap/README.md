# gen_pcap - PCAP 包生成器

一个用于生成网络包（特别是TCP和HTTP包）的Rust库，可以创建PCAP文件用于网络测试和分析。

## 📋 功能特性

- **🌐 多TCP会话生成**: 支持创建指定数量的TCP会话，可配置IP地址范围和端口范围
- **📡 IP地址范围支持**: 支持单个IP或IP范围（如 10.0.0.1-10.0.0.100）
- **🔌 端口范围支持**: 支持单个端口或端口范围（如 80-443）
- **🤝 TCP包构造**: 支持完整的TCP三次握手和数据处理
- **🌐 HTTP报文构造**: 支持HTTP/1.1请求和响应的构造
- **📝 多种HTTP方法**: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
- **⚙️ 灵活的头部设置**: 支持自定义HTTP头部
- **💻 命令行界面**: 提供易用的CLI工具
- **📁 PCAP文件生成**: 直接生成可用于Wireshark分析的PCAP文件
- **🏗️ 模块化架构**: 清晰的模块分离，易于扩展和维护

## 🚀 快速开始

### 命令行使用

#### 基本TCP会话生成

```bash
# 生成5个TCP会话，使用IP范围和端口范围
cargo run -- -n 5 -s "10.0.0.1-10.0.0.5" -d "192.168.1.100-192.168.1.200" -p "80-443" -o "tcp_sessions.pcap"

# 生成10个会话，仅TCP三次握手
cargo run -- -n 10 -s "172.16.0.1-172.16.0.20" -d "10.0.0.100" -p "22,80,443" -o "handshakes.pcap"
```

#### 包含HTTP流量的会话

```bash
# 生成带HTTP流量的会话
cargo run -- -n 3 -s "10.0.0.1" -d "192.168.1.100" --http --http-host "api.example.com" --http-uris "/api/v1/users,/api/v1/orders,/health" -o "http_sessions.pcap"

# 复杂场景：多IP范围、多端口、HTTP流量
cargo run -- -n 10 -s "192.168.0.1-192.168.0.100" -d "10.10.10.1-10.10.10.20" --src-port "30000-60000" -p "80,443,8080" --http --http-host "webapp.company.com" --http-uris "/login,/dashboard,/api/data" -o "complex_traffic.pcap"
```

#### 传统模式（向后兼容）

```bash
# 使用原有的示例流量生成模式
cargo run -- --legacy
```

### 命令行参数

| 参数 | 简写 | 长参数 | 描述 | 默认值 |
|------|------|--------|------|--------|
| 会话数量 | `-n` | `--sessions` | TCP会话数量 | 1 |
| 源IP | `-s` | `--src-ip` | 源IP地址范围 | 10.10.1.100 |
| 目标IP | `-d` | `--dst-ip` | 目标IP地址范围 | 192.168.1.100 |
| 源端口 | - | `--src-port` | 源端口范围 | 30000-40000 |
| 目标端口 | `-p` | `--dst-port` | 目标端口范围 | 80 |
| HTTP流量 | - | `--http` | 包含HTTP请求/响应 | false |
| HTTP主机 | - | `--http-host` | HTTP请求的Host头 | example.com |
| HTTP URIs | - | `--http-uris` | HTTP请求URI列表（逗号分隔） | / |
| 输出文件 | `-o` | `--output` | PCAP输出文件名 | output.pcap |
| 传统模式 | - | `--legacy` | 使用传统模式生成示例流量 | false |

## 📚 库使用指南

### 架构概览

`gen_pcap` 采用模块化架构设计：

```
src/
├── lib.rs          # 统一的公共API和兼容性函数
├── main.rs         # 命令行工具实现
├── core/           # 核心抽象和类型定义
│   ├── network.rs  # 网络连接和IP/端口范围
│   ├── session.rs  # TCP会话和应用流抽象
│   └── error.rs    # 错误类型定义
├── tcp/            # TCP协议实现
│   ├── packet.rs   # TCP包构建函数
│   ├── connection.rs # TCP连接状态管理
│   └── handshake.rs # TCP握手逻辑
├── http/           # HTTP协议实现
│   ├── request.rs  # HTTP请求构建
│   ├── response.rs # HTTP响应构建
│   └── flow.rs     # HTTP流量生成
└── session/        # 会话管理和配置
    ├── config.rs   # 会话配置
    ├── builder.rs  # 会话构建器
    └── factory.rs  # 会话工厂
```

### 基本TCP包构造

```rust
use gen_pcap::{build_tcp_packet, TcpPacketParams};
use pnet::packet::tcp::TcpFlags;
use std::net::Ipv4Addr;

let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
let dst_mac = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
let src_ip = Ipv4Addr::new(10, 10, 1, 100);
let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

// 使用参数结构体构建TCP包
let params = TcpPacketParams::new(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::SYN
);
let tcp_packet = build_tcp_packet(params);
```

### 带数据的TCP包构造

```rust
use gen_pcap::{build_tcp_packet_with_data, TcpPacketWithDataParams};

let payload = b"Hello, World!";
let params = TcpPacketWithDataParams::new(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::ACK | TcpFlags::PSH,
    payload.to_vec()
);
let tcp_packet = build_tcp_packet_with_data(params);
```

### 多TCP会话生成（推荐方式）

```rust
use gen_pcap::{TcpSessionConfig, IpRange, PortRange, ApplicationFlowType};
use std::net::Ipv4Addr;

// 创建配置
let config = TcpSessionConfig::new()
    .with_session_count(5)
    .with_src_ip_range(IpRange::new(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 100)
    ))
    .with_dst_ip_range(IpRange::from_string("192.168.1.100-192.168.1.200").unwrap())
    .with_dst_port_range(PortRange::from_string("80-443").unwrap())
    .with_http(
        vec!["/api/v1/users".to_string(), "/health".to_string()],
        "api.example.com".to_string()
    );

// 生成会话
let sessions = config.generate_sessions();

// 为每个会话生成数据包
for session in sessions {
    let flow = ApplicationFlowType::Http(
        gen_pcap::HttpFlow::new(
            vec!["/api/test".to_string()],
            "test.example.com".to_string()
        )
    );
    let packets = session.generate_packets(&flow);
    println!("会话 {} -> {}:{} 生成 {} 个数据包",
        session.connection.src_ip,
        session.connection.dst_ip,
        session.connection.dst_port,
        packets.len());
}
```

### 使用Session Factory

```rust
use gen_pcap::SessionFactory;

let factory = SessionFactory::new()
    .with_macs(src_mac, dst_mac);

let session = factory.create_session(
    Ipv4Addr::new(10, 0, 0, 1),
    Ipv4Addr::new(192, 168, 1, 100),
    12345, 80, ApplicationFlowType::TcpOnly
);
```

### HTTP GET请求

```rust
use gen_pcap::build_http_get_packet;
use pnet::packet::tcp::TcpFlags;

let http_get = build_http_get_packet(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::ACK | TcpFlags::PSH,
    "/api/users", "api.example.com"
);
```

### HTTP POST请求

```rust
use gen_pcap::build_http_post_packet;

let post_data = b"{\"name\": \"Alice\", \"age\": 30}";
let http_post = build_http_post_packet(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::ACK | TcpFlags::PSH,
    "/api/users", "api.example.com",
    "application/json", post_data
);
```

### HTTP响应

```rust
use gen_pcap::{build_http_response_packet_simple, HttpStatusCode};

let response = build_http_response_packet_simple(
    dst_mac, src_mac, dst_ip, src_ip,
    8080, 12345, 2000, 1000, TcpFlags::ACK | TcpFlags::PSH,
    HttpStatusCode::Ok,
    "application/json",
    b"{\"status\": \"success\"}"
);
```

### 完整HTTP流程生成

```rust
use gen_pcap::build_http_get_flow_packets;

let complete_flow = build_http_get_flow_packets(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 80, 1000, 0, 12345,  // TCP参数
    "/api/users", "api.example.com",  // HTTP参数
    b"{\"users\": []}"  // 响应体
);
// 返回包含握手、请求、响应的完整数据包序列
```

### 高级HTTP请求构造

```rust
use gen_pcap::{HttpRequest, HttpMethod, HttpVersion, build_http_request_packet};

let request = HttpRequest::new(HttpMethod::PUT, "/api/users/123".to_string())
    .with_version(HttpVersion::Http1_1)
    .add_header("Authorization".to_string(), "Bearer token123".to_string())
    .add_header("Content-Type".to_string(), "application/json".to_string())
    .with_body(b"{\"name\": \"Bob\"}".to_vec());

let packet = build_http_request_packet(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::ACK | TcpFlags::PSH,
    &request
);
```

## 🎯 API 参考

### 核心类型

#### NetworkConnection
网络连接信息
```rust
pub struct NetworkConnection {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}
```

#### TcpSession
单个TCP会话
```rust
pub struct TcpSession {
    pub connection: NetworkConnection,
    pub isn: u32,
}

impl TcpSession {
    pub fn new(connection: NetworkConnection, isn: u32) -> Self
    pub fn generate_packets(&self, flow: &dyn ApplicationFlow) -> Vec<Vec<u8>>
}
```

#### ApplicationFlow Trait
应用流量生成抽象
```rust
pub trait ApplicationFlow {
    fn generate_packets(&self, session: &TcpSession) -> Vec<Vec<u8>>;
    fn name(&self) -> &'static str;
}
```

### 配置类型

#### IpRange
IP地址范围管理
```rust
pub struct IpRange {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl IpRange {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self
    pub fn from_string(range_str: &str) -> Result<Self, Box<dyn std::error::Error>>
    pub fn contains(&self, ip: Ipv4Addr) -> bool
    pub fn random_ip(&self) -> Ipv4Addr
    pub fn count(&self) -> u64
}
```

#### PortRange
端口范围管理
```rust
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self
    pub fn from_string(range_str: &str) -> Result<Self, Box<dyn std::error::Error>>
    pub fn random_port(&self) -> u16
    pub fn count(&self) -> u32
}
```

#### TcpSessionConfig
TCP会话配置
```rust
pub struct TcpSessionConfig {
    pub src_ip_range: IpRange,
    pub dst_ip_range: IpRange,
    pub src_port_range: PortRange,
    pub dst_port_range: PortRange,
    pub session_count: u32,
    pub application_flow: ApplicationFlowType,
}

impl Default for TcpSessionConfig {
    fn default() -> Self { Self::new() }
}

impl TcpSessionConfig {
    pub fn new() -> Self
    pub fn with_src_ip_range(mut self, range: IpRange) -> Self
    pub fn with_dst_ip_range(mut self, range: IpRange) -> Self
    pub fn with_src_port_range(mut self, range: PortRange) -> Self
    pub fn with_dst_port_range(mut self, range: PortRange) -> Self
    pub fn with_session_count(mut self, count: u32) -> Self
    pub fn with_http(mut self, uris: Vec<String>, host: String) -> Self
    pub fn generate_sessions(&self) -> Vec<TcpSession>
    pub fn generate_sessions_with_macs(&self, src_mac: [u8; 6], dst_mac: [u8; 6]) -> Vec<TcpSession>
}
```

### HTTP相关

#### HTTP方法
- `HttpMethod::GET`
- `HttpMethod::POST`
- `HttpMethod::PUT`
- `HttpMethod::DELETE`
- `HttpMethod::HEAD`
- `HttpMethod::OPTIONS`
- `HttpMethod::PATCH`

#### HTTP版本
- `HttpVersion::Http1_0`
- `HttpVersion::Http1_1`
- `HttpVersion::Http2_0`

#### HTTP状态码
- `HttpStatusCode::Ok` (200)
- `HttpStatusCode::NotFound` (404)
- `HttpStatusCode::InternalServerError` (500)
- `HttpStatusCode::BadRequest` (400)
- `HttpStatusCode::Unauthorized` (401)
- `HttpStatusCode::Forbidden` (403)
- `HttpStatusCode::Custom(u16)` (自定义状态码)

### TCP包构建函数

```rust
// 基本TCP包
pub fn build_tcp_packet(params: TcpPacketParams) -> Vec<u8>

// 带数据的TCP包
pub fn build_tcp_packet_with_data(params: TcpPacketWithDataParams) -> Vec<u8>

// TCP三次握手
pub fn build_tcp_handshake_packets(
    src_mac: [u8; 6], dst_mac: [u8; 6],
    src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
    src_port: u16, dst_port: u16,
    isn: u32
) -> (Vec<Vec<u8>>, TcpConnection)
```

### HTTP包构建函数

```rust
// HTTP GET请求
pub fn build_http_get_packet(/* 参数 */) -> Vec<u8>

// HTTP POST请求
pub fn build_http_post_packet(/* 参数 */) -> Vec<u8>

// HTTP响应
pub fn build_http_response_packet_simple(/* 参数 */) -> Vec<u8>

// 完整HTTP流程
pub fn build_http_get_flow_packets(/* 参数 */) -> Vec<Vec<u8>>
pub fn build_http_post_flow_packets(/* 参数 */) -> Vec<Vec<u8>>
pub fn build_http_get_post_flow_packets(/* 参数 */) -> Vec<Vec<u8>>
```

## 🎯 使用场景

### 网络测试
- 模拟大量TCP连接进行负载测试
- 生成特定模式的网络流量进行安全测试
- 创建网络设备测试数据

### 开发调试
- 生成测试数据验证网络应用
- 模拟客户端行为测试服务器性能
- 创建协议分析样本

### 安全研究
- 生成恶意流量样本进行检测规则测试
- 模拟网络攻击场景
- 创建入侵检测系统测试数据

## 🛠️ 依赖项

- `pnet` - 网络包处理
- `pcap` - PCAP文件操作
- `libc` - 系统调用

## 📄 许可证

MIT License

---

## 🔄 更新日志

### v2.0.0 (重构版本)
- ✨ **架构重构**: 采用模块化设计，代码结构更清晰
- 🗑️ **移除重复代码**: 统一包生成架构，消除重复实现
- 🚀 **性能优化**: 减少内存分配，提高构建效率
- 📚 **API改进**: 更一致的API设计，更好的类型安全
- 🔧 **参数结构体**: 为复杂函数引入参数结构体，减少参数数量
- 🛡️ **错误处理**: 改进的错误类型和处理机制
- 📖 **文档完善**: 更详细的API文档和使用示例

### 向后兼容性
- 保持所有现有公共API的兼容性
- CLI接口完全兼容
- 现有代码无需修改即可使用新版本