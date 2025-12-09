# PCAP解析器基础类型

本模块定义了PCAP解析器使用的所有核心数据结构。

## 模块结构

### packet.rs - 数据包类型
- `Packet`: 网络数据包的完整表示
- `PacketHeader`: 数据包头信息（时间戳、长度等）
- `Protocol`: 协议类型枚举
- `TcpFlags`: TCP标志位
- `PacketLayer`: 协议层类型

### flow.rs - 流类型
- `FlowKey`: 流的唯一标识（自动排序的五元组）
- `FlowDirection`: 流方向（客户端到服务器/服务器到客户端）
- `FlowStats`: 流统计信息
- `FiveTuple`: 原始五元组
- `FlowLabel`: 流标签（协议分类）

### stream.rs - 流信息类型
- `TcpStream`: TCP流的完整信息
- `TcpState`: TCP连接状态
- `TcpHandshake`: TCP握手状态
- `TcpClose`: TCP关闭状态
- `ConnectionInfo`: 连接详细信息
- `StreamEvent`: 流事件类型
- `StreamEventRecord`: 流事件记录

## 主要特性

1. **自动序列化/反序列化**: 所有类型都支持serde
2. **高效的流键值**: FlowKey自动处理IP和端口排序，确保双向流具有相同的键值
3. **完整的TCP状态跟踪**: 支持握手、数据传输、关闭等所有状态
4. **详细的统计信息**: 包含包数、字节数、速率、吞吐量等
5. **流重组支持**: TcpStream支持数据包重组

## 使用示例

```rust
use pcap_steam_anylizer::types::*;

// 创建一个数据包
let header = PacketHeader::new(timestamp_sec, timestamp_usec, caplen, len);
let mut packet = Packet::new(header, data);
packet.protocols.push(Protocol::Tcp);

// 创建流键值
let flow_key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, 6);

// 创建TCP流
let mut stream = TcpStream::new(flow_key);
stream.update_state(TcpState::Established, timestamp);

// 更新流统计
let mut stats = FlowStats::new();
stats.update(bytes, FlowDirection::ClientToServer, timestamp);
```

## 注意事项

- 所有时间戳使用微秒精度
- FlowKey内部对IP地址和端口进行排序，便于高效查找
- TCP序列号处理考虑了乱序和重传场景
- 流统计会自动计算各种性能指标