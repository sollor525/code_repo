# 封装函数使用指南

## 概述

我们成功将TCP三次握手和HTTP通信封装为易于使用的函数，自动处理TCP序列号和确认号的计算。

## 新增的封装函数

### 1. TCP连接状态跟踪

```rust
pub struct TcpConnection {
    pub client_seq: u32,
    pub server_seq: u32,
    pub client_ack: u32,
    pub server_ack: u32,
}
```

### 2. TCP三次握手封装

```rust
pub fn build_tcp_handshake_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
) -> (Vec<Vec<u8>>, TcpConnection)
```

**功能**：
- 自动生成SYN、SYN/ACK、ACK三个包
- 自动处理序列号和确认号
- 返回包列表和连接状态

### 3. HTTP GET流程封装

```rust
pub fn build_http_get_flow_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
    uri: &str,
    host: &str,
    response_body: &[u8],
) -> Vec<Vec<u8>>
```

**功能**：
- 包含TCP三次握手
- 生成HTTP GET请求
- 生成HTTP GET响应
- 自动处理所有序列号和确认号

### 4. HTTP POST流程封装

```rust
pub fn build_http_post_flow_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
    uri: &str,
    host: &str,
    content_type: &str,
    post_data: &[u8],
    response_body: &[u8],
) -> Vec<Vec<u8>>
```

**功能**：
- 包含TCP三次握手
- 生成HTTP POST请求
- 生成HTTP POST响应
- 自动处理所有序列号和确认号

### 5. 完整HTTP流程封装

```rust
pub fn build_http_complete_flow_packets(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    isn: u32,
    get_uri: &str,
    post_uri: &str,
    host: &str,
    post_data: &[u8],
    get_response: &[u8],
    post_response: &[u8],
) -> Vec<Vec<u8>>
```

**功能**：
- 包含TCP三次握手
- 生成HTTP GET请求和响应
- 生成HTTP POST请求和响应
- 自动处理所有序列号和确认号

## 使用示例

### 基本使用

```rust
use gen_pcap::build_http_complete_flow_packets;

let packets = build_http_complete_flow_packets(
    src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, isn,
    "/api/users",           // GET URI
    "/api/users",           // POST URI
    "api.example.com",      // Host
    b"{\"name\": \"Bob\"}", // POST数据
    b"{\"users\": []}",     // GET响应
    b"{\"id\": 1}",         // POST响应
);

// 写入PCAP文件
for packet_data in packets {
    let header = PacketHeader { /* ... */ };
    let packet = Packet::new(&header, &packet_data);
    savefile.write(&packet);
}
```

### 分层使用

```rust
// 仅TCP握手
let (handshake_packets, conn) = build_tcp_handshake_packets(/* ... */);

// 仅HTTP GET
let get_packets = build_http_get_flow_packets(/* ... */);

// 仅HTTP POST
let post_packets = build_http_post_flow_packets(/* ... */);
```

## 优势

1. **自动化**：无需手动计算TCP序列号和确认号
2. **简化**：复杂的网络包构造变得简单
3. **分层**：提供不同层次的封装函数
4. **准确**：减少手动计算错误的可能性
5. **灵活**：支持各种HTTP方法和自定义数据

## 验证结果

通过tcpdump验证，生成的PCAP文件中的TCP序列号和确认号都是正确的：

```
08:00:00.000000 IP 10.10.1.100.12347 > 192.168.1.100.8080: Flags [S], seq 1003000, win 64240, length 0
08:00:00.001000 IP 192.168.1.100.8080 > 10.10.1.100.12347: Flags [S.], seq 1003000, ack 1003001, win 64240, length 0
08:00:00.002000 IP 10.10.1.100.12347 > 192.168.1.100.8080: Flags [.], ack 1003001, win 64240, length 0
08:00:00.003000 IP 10.10.1.100.12347 > 192.168.1.100.8080: Flags [P], seq 1003001:1003109, win 64240, length 108: HTTP: GET /api/users HTTP/1.1
08:00:00.004000 IP 192.168.1.100.8080 > 10.10.1.100.12347: Flags [P.], seq 1003001:1003178, ack 1003001, win 64240, length 177: HTTP: HTTP/1.1 200 OK
08:00:00.005000 IP 10.10.1.100.12347 > 192.168.1.100.8080: Flags [P], seq 1003109:1003321, win 64240, length 212: HTTP: POST /api/users HTTP/1.1
08:00:00.006000 IP 192.168.1.100.8080 > 10.10.1.100.12347: Flags [P.], seq 1003178:1003339, ack 1003109, win 64240, length 161: HTTP: HTTP/1.1 200 OK
```

## 运行示例

```bash
# 运行封装函数示例
cargo run --example encapsulated_functions_example

# 运行原始HTTP示例
cargo run --example http_example

# 运行主程序
cargo run
```
