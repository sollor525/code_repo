# PCAP 流分析器

一个 PCAP 文件分析工具。**核心用途是验证 NPatch 阻断设备是否成功拦截了 TCP 连接**，
同时提供通用的 TCP 流分析（三次握手、四次挥手、RST 重置、流统计）。

## 功能特性

### NPatch 阻断验证
逐流判定 NPatch 阻断是否生效，覆盖 5 种验证模式：单向阻断（通用）、
ACK 阻断、SYN 阻断、Hijack 劫持、Web 扫描防护。详见
[docs/NPATCH_VERIFICATION.md](docs/NPATCH_VERIFICATION.md)。

### TCP 流分析
- 读取 PCAP 文件，解析二/三/四层信息（基于 `etherparse`）
- 基于五元组重建 TCP 流（双向报文归并到同一条流）
- TCP 连接状态跟踪：三次握手、四次挥手、RST 重置
- 流统计：报文数、字节数、双向分量、持续时间、首/末包时间
- 表格 / JSON / CSV 三种输出格式，支持过滤与排序

### 处理模型
程序始终采用「按流分组的多线程」处理 —— 不同流并行、同一流内报文按时间戳
有序由单线程处理，由程序自身保证流分析的正确性，无需任何线程相关参数。

## 快速开始

### 依赖

- Rust 工具链（edition 2024，需 Rust ≥ 1.85）
- 系统库 `libpcap-dev`（`pcap` crate 依赖）

### 编译

```bash
cargo build              # 开发模式
cargo build --release    # 发布模式（优化）
```

### 基本使用

```bash
# 分析 PCAP 文件，输出表格
./target/release/pcap_steam_anylizer input.pcap

# 输出 JSON 到文件
./target/release/pcap_steam_anylizer input.pcap -f json -o flows.json

# 过滤与排序
./target/release/pcap_steam_anylizer input.pcap --dst-port 80 -s packet_count --desc

# 验证 NPatch 单向阻断是否成功
./target/release/pcap_steam_anylizer input.pcap --one-way-blocking
```

## 命令行选项

### 输入输出
- `<INPUT>`: PCAP 文件路径（必需）
- `-o, --output`: 输出文件路径（默认标准输出）
- `-f, --format`: 输出格式 `[table|json|csv]`（默认 table）

### 过滤选项
- `-p, --protocol`: 协议过滤 `[tcp|udp|icmp]`
- `--src-ip` / `--dst-ip`: 源/目的 IP 过滤
- `--src-port` / `--dst-port`: 源/目的端口过滤
- `--min-packets` / `--max-packets`: 报文数量范围
- `--min-bytes` / `--max-bytes`: 字节数范围
- `--complete`: 只保留完整建立的 TCP 连接

> 过滤选项同样适用于下方的阻断验证模式，可自由组合，例如
> `--one-way-blocking --min-packets 3`。

### 排序选项
- `-s, --sort`: 排序字段（`flow_id`、`src_ip`、`src_port`、`dst_ip`、`dst_port`、
  `protocol`、`packet_count`、`byte_count`、`duration`、`first_packet_time`、
  `last_packet_time`、`state`）
- `--desc`: 降序排列（默认升序）

### 显示选项
- `-v, --verbose`: 显示详细信息
- `--no-progress`: 禁用进度条

### NPatch 阻断验证选项
以下开关互斥，一次只能指定一个：
- `--one-way-blocking`: 验证单向阻断是否成功（服务器返回有效数据前，NPatch 已注入 RST 或 hijack 报文）
- `--verify-ack-block`: 验证 ACK 阻断（三次握手完成后注入 RST 窗口888）
- `--verify-syn-block`: 验证 SYN 阻断（三次握手完成前注入 RST 窗口888）
- `--verify-hijack`: 验证 Hijack 劫持（注入伪造响应 PSH/ACK 窗口888）
- `--verify-web-scan`: 验证 Web 扫描防护（web 流被注入 RST 或 hijack 报文）

未被成功阻断的会话会被导出到 `npatch_verify_<模式>_not_blocked.pcap` 便于复查。

## 输出示例

### 表格格式
```
+-------------------------------------------------+----------------------+-------------------+-------+-------+---------+-------+----------+
| Flow                                            | Client               | Server            | Proto | State | Packets | Bytes | Duration |
| 10.105.108.253:35768 -> 10.105.108.23:443 (TCP) | 10.105.108.253:35768 | 10.105.108.23:443 | TCP   | RESET | 6       | 0 B   | 1ms      |
+-------------------------------------------------+----------------------+-------------------+-------+-------+---------+-------+----------+
```

### JSON 格式
JSON 输出为流对象数组：

```json
[
  {
    "flow_id": "10.105.108.253:35768 -> 10.105.108.23:443 (TCP)",
    "five_tuple": { "client_ip": "10.105.108.253", "client_port": 35768,
                    "server_ip": "10.105.108.23", "server_port": 443,
                    "protocol": "TCP", "protocol_number": 6 },
    "state": "RESET",
    "stats": { "packet_count": 6, "byte_count": 0, "duration_micros": 1147 },
    "connection": { "handshake": { "complete": true },
                    "close": { "complete": true, "reset": true } }
  }
]
```

### 阻断验证报告
```
# NPatch 阻断验证报告 — 模式: ACK 阻断
流ID: 10.105.108.253:35768 -> 10.105.108.23:443 (TCP)
  阻断结果: 已阻断 ✓
  判定原因: ACK 阻断成功：三次握手完成后、服务器返回有效数据前收到 RST(窗口888)
  阻断报文: 标志位=RST 窗口=888 TTL=60 IP-ID=0x8866 方向=朝向客户端 负载=0字节

# 统计摘要:
# 待验证流数: 1
# 已成功阻断: 1
# 未成功阻断: 0
```

## 项目结构

```
src/
├── main.rs            # 主程序入口、CLI(Args)、App
├── lib.rs             # 库入口
├── pcap/
│   ├── reader.rs      # PCAP 文件读取器（自实现，处理字节序/精度）
│   ├── parser.rs      # 数据包解析器（基于 etherparse）
│   └── writer.rs      # PCAP 文件写入器（导出未阻断流）
├── types/
│   ├── packet.rs      # Packet / TcpFlags
│   ├── packet_info.rs # PacketInfo（分析用精简结构）
│   ├── flow.rs        # FlowKey（双向归一化）/ FlowStats
│   └── stream.rs      # TcpStream / TcpState / BlockingMode / 阻断验证逻辑
├── stream/
│   └── manager.rs     # StreamManager —— TCP 状态机驱动
├── output/
│   └── formatter.rs   # 表格 / JSON / CSV 格式化
├── rayon_parallel.rs  # RayonProcessor —— 按流并行处理
└── time_limit.rs      # 使用期限检查
```

处理流水线：`PcapReader` → `PacketParser` → `PacketInfo` →
`RayonProcessor::process_packets_by_flow` → `StreamManager` → 逐流 `TcpStream`。

## 测试

```bash
cargo test                          # 全部测试
cargo test --test handshake_reset   # 集成测试
cargo test <name>                   # 运行名称匹配的测试
```

集成测试（`tests/handshake_reset.rs`）在内存中构造 PCAP 字节流并走完整流水线，
覆盖握手判定、RST 重置、四次挥手、解析边界以及全部 5 种阻断验证模式。

## 文档

- [docs/NPATCH_VERIFICATION.md](docs/NPATCH_VERIFICATION.md) —— 阻断验证模式与 NPatch 签名说明
- [docs/BUGFIXES.md](docs/BUGFIXES.md) —— 解析器/流引擎的缺陷修复记录
- [CLAUDE.md](CLAUDE.md) —— 面向 Claude Code 的代码库说明

> 注意：本仓库根 `.gitignore` 忽略所有 `*.md`、`*.pcap`、`*.PCAP` 文件，
> 故文档与 `pcap_file/` 样本默认不被版本控制跟踪，需要时用 `git add -f`。

## 依赖库

`pcap`、`etherparse`（协议解析）、`rayon`（并行）、`hashbrown`、
`clap`（命令行）、`serde` / `serde_json`、`prettytable-rs`、`indicatif`、`chrono`。

## 许可证

本项目采用 MIT 许可证。
