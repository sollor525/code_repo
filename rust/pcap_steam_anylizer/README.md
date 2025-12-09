# PCAP流分析器

一个专业的PCAP文件解析器，支持TCP流分析、协议解析、分段重组和连接状态跟踪。

## 功能特性

### 核心功能
- ✅ 读取PCAP文件，解析二/三/四层信息
- ✅ 支持VLAN/MPLS标签解析
- ✅ 获取所有TCP流信息（基于五元组）
- ✅ TCP分段重组和IP分片重组
- ✅ TCP乱序报文识别和处理
- ✅ TCP连接状态跟踪（三次握手、四次挥手、Reset）

### 输出信息
- 五元组（源IP、目的IP、源端口、目的端口、协议）
- 流的报文总数和字节总数
- 流状态（完整/不完整）
- 三次握手状态（是否完成）
- 四次挥手状态（是否正常关闭）
- Reset导致的流结束标识
- 连接持续时间
- 首个和最后一个数据包时间戳

## 快速开始

### 安装依赖

本项目使用Rust编写，需要安装Rust工具链：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 编译

```bash
# 开发模式编译
cargo build

# 发布模式编译（优化）
cargo build --release
```

### 基本使用

```bash
# 分析PCAP文件，输出表格格式
./target/release/pcap_steam_anylizer input.pcap

# 输出JSON格式到文件
./target/release/pcap_steam_anylizer input.pcap -f json -o flows.json

# 过滤特定协议
./target/release/pcap_steam_anylizer input.pcap -p tcp

# 过滤特定端口
./target/release/pcap_steam_anylizer input.pcap --dst-port 80

# 只显示完整建立的TCP连接
./target/release/pcap_steam_anylizer input.pcap --complete

# 按数据包数量排序
./target/release/pcap_steam_anylizer input.pcap -s packet_count --desc
```

## 命令行选项

### 输入输出
- `<INPUT>`: PCAP文件路径（必需）
- `-o, --output`: 输出文件路径（可选，默认标准输出）
- `-f, --format`: 输出格式 [table|json|csv]（默认table）

### 过滤选项
- `-p, --protocol`: 协议过滤 [tcp|udp|icmp]
- `--src-ip`: 源IP地址过滤
- `--dst-ip`: 目的IP地址过滤
- `--src-port`: 源端口过滤
- `--dst-port`: 目的端口过滤
- `--min-packets/--max-packets`: 数据包数量范围过滤
- `--min-bytes/--max-bytes`: 字节数范围过滤

### 排序选项
- `-s, --sort`: 排序字段
  - flow_id, src_ip, src_port, dst_ip, dst_port
  - protocol, packet_count, byte_count, duration
  - first_packet_time, last_packet_time, state
- `--desc`: 降序排列（默认升序）

### 显示选项
- `-v, --verbose`: 显示详细信息
- `--complete`: 只显示完整建立的TCP连接
- `--no-progress`: 禁用进度条

## 输出格式示例

### 表格格式
```
┌────┬───────────────┬──────────┬───────────────┬──────────┬───────────┬──────────────┬────────────┬──────────┬──────────┬───────────────┬───────────────┬────────┐
│ #  │ 源IP          │ 源端口   │ 目的IP        │ 目的端口 │ 协议     │ 数据包数量 │ 字节数      │ 状态      │ 握手     │ 挥手         │ 首包时间     │ 持续时间│
├────┼───────────────┼──────────┼───────────────┼──────────┼───────────┼──────────────┼────────────┼──────────┼──────────┼───────────────┼───────────────┼────────┤
│ 1  │ 192.168.1.100 │ 12345    │ 10.0.0.1      │ 80       │ TCP       │ 25          │ 15.3 KB    │ 已建立   │ 是       │ 是           │ 14:23:45.123 │ 5.2s   │
└────┴───────────────┴──────────┴───────────────┴──────────┴───────────┴──────────────┴────────────┴──────────┴──────────┴───────────────┴───────────────┴────────┘
```

### JSON格式
```json
{
  "total_streams": 1,
  "streams": [
    {
      "flow_id": 1,
      "five_tuple": {
        "src_ip": "192.168.1.100",
        "src_port": 12345,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": 6
      },
      "packet_count": 25,
      "byte_count": 15678,
      "state": "ESTABLISHED",
      "handshake_completed": true,
      "close_completed": true,
      "reset_by_peer": false,
      "duration_ms": 5200,
      "first_packet_time": "2024-01-01T14:23:45.123Z",
      "last_packet_time": "2024-01-01T14:23:50.323Z"
    }
  ]
}
```

## 项目结构

```
src/
├── main.rs              # 主程序入口和CLI
├── lib.rs               # 库入口
├── pcap/                # PCAP文件处理
│   ├── reader.rs        # PCAP文件读取器
│   └── parser.rs        # 数据包解析器
├── protocol/            # 协议解析模块
│   ├── ethernet.rs      # 以太网帧解析
│   ├── ip.rs           # IP协议解析
│   ├── tcp.rs          # TCP协议解析
│   ├── vlan.rs         # VLAN标签解析
│   └── mpls.rs         # MPLS标签解析
├── stream/              # 流管理和重组
│   ├── manager.rs      # 流管理器
│   ├── reassembler.rs  # TCP重组器
│   ├── fragment.rs     # IP分片重组
│   └── state.rs        # TCP连接状态跟踪
├── types/               # 数据类型定义
│   ├── packet.rs       # 数据包类型
│   ├── flow.rs         # 流类型
│   └── stream.rs       # 流信息类型
└── output/              # 输出格式化
    └── formatter.rs    # 输出格式化器
```

## 技术特点

### 性能优化
- 使用高性能的hashbrown HashMap
- 流式处理，支持大文件
- 智能内存管理和缓存策略
- 可配置的缓冲区大小

### 协议支持
- 二层：Ethernet（包括VLAN标签）
- 三层：IPv4/IPv6（包括MPLS标签）
- 四层：TCP/UDP/ICMP
- 应用层：自动识别（HTTP/HTTPS/DNS等）

### TCP特性
- 完整TCP状态机实现
- 分段重组和乱序处理
- IP分片重组
- 连接质量分析
- 重传检测

## 依赖库

- `pcap`: PCAP文件读取
- `etherparse`: 网络协议解析
- `hashbrown`: 高性能HashMap
- `clap`: 命令行参数解析
- `serde`: 序列化支持
- `indicatif`: 进度条显示

## 示例

查看更多示例程序：

```bash
# 运行PCAP读取示例
cargo run --example pcap_reader_demo

# 运行格式化演示
cargo run --example format_demo

# 运行流管理演示
cargo run --example stream_manager_demo
```

## 许可证

本项目采用MIT许可证。