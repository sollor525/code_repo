# gen_pcap - PCAP 包生成器

一个用于生成网络包（特别是TCP和HTTP包）的Rust库，可以创建PCAP文件用于网络测试和分析。

## 功能特性

- **TCP包构造**: 支持完整的TCP三次握手和数据处理
- **HTTP报文构造**: 支持HTTP/1.1请求和响应的构造
- **多种HTTP方法**: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
- **灵活的头部设置**: 支持自定义HTTP头部
- **PCAP文件生成**: 直接生成可用于Wireshark分析的PCAP文件

## 快速开始

### 基本TCP包构造

```rust
use gen_pcap::build_tcp_packet;
use pnet::packet::tcp::TcpFlags;
use std::net::Ipv4Addr;

let src_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
let dst_mac = [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c];
let src_ip = Ipv4Addr::new(10, 10, 1, 100);
let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

let tcp_packet = build_tcp_packet(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::SYN
);
```

### HTTP GET请求

```rust
use gen_pcap::build_http_get_packet;
use pnet::packet::tcp::TcpFlags;

let http_get = build_http_get_packet(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::ACK,
    "/api/users", "api.example.com"
);
```

### HTTP POST请求

```rust
use gen_pcap::build_http_post_packet;

let post_data = b"{\"name\": \"Alice\", \"age\": 30}";
let http_post = build_http_post_packet(
    src_mac, dst_mac, src_ip, dst_ip,
    12345, 8080, 1000, 2000, TcpFlags::ACK,
    "/api/users", "api.example.com",
    "application/json", post_data
);
```

### HTTP响应

```rust
use gen_pcap::{build_http_response_packet_simple, HttpStatusCode};

let response = build_http_response_packet_simple(
    dst_mac, src_mac, dst_ip, src_ip,
    8080, 12345, 2000, 1000, TcpFlags::ACK,
    HttpStatusCode::Ok,
    "application/json",
    b"{\"status\": \"success\"}"
);
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
    12345, 8080, 1000, 2000, TcpFlags::ACK,
    &request
);
```

### 高级HTTP响应构造

```rust
use gen_pcap::{HttpResponse, HttpStatusCode, HttpVersion, build_http_response_packet};

let response = HttpResponse::new(HttpStatusCode::NotFound)
    .with_version(HttpVersion::Http1_1)
    .add_header("Server".to_string(), "nginx/1.18.0".to_string())
    .add_header("Content-Type".to_string(), "text/html".to_string())
    .with_body(b"<html><body><h1>404 Not Found</h1></body></html>".to_vec());

let packet = build_http_response_packet(
    dst_mac, src_mac, dst_ip, src_ip,
    8080, 12345, 2000, 1000, TcpFlags::ACK,
    &response
);
```

## 运行示例

```bash
# 运行基本示例
cargo run

# 运行HTTP示例
cargo run --example http_example
```

## API 参考

### HTTP方法

- `HttpMethod::GET`
- `HttpMethod::POST`
- `HttpMethod::PUT`
- `HttpMethod::DELETE`
- `HttpMethod::HEAD`
- `HttpMethod::OPTIONS`
- `HttpMethod::PATCH`

### HTTP版本

- `HttpVersion::Http1_0`
- `HttpVersion::Http1_1`
- `HttpVersion::Http2_0`

### HTTP状态码

- `HttpStatusCode::Ok` (200)
- `HttpStatusCode::NotFound` (404)
- `HttpStatusCode::InternalServerError` (500)
- `HttpStatusCode::BadRequest` (400)
- `HttpStatusCode::Unauthorized` (401)
- `HttpStatusCode::Forbidden` (403)
- `HttpStatusCode::Custom(u16)` (自定义状态码)

### 便利函数

- `build_http_get_packet()` - 构建GET请求包
- `build_http_post_packet()` - 构建POST请求包
- `build_http_response_packet_simple()` - 构建简单响应包
- `build_http_request_packet()` - 构建自定义请求包
- `build_http_response_packet()` - 构建自定义响应包
- `build_tcp_packet_with_data()` - 构建包含数据的TCP包

## 依赖项

- `pnet` - 网络包处理
- `pcap` - PCAP文件操作
- `libc` - 系统调用

## 许可证

MIT License
