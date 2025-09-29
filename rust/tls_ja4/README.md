# TLS JA4/JA3 Fingerprint Extractor

一个高性能的Rust程序，用于从pcap文件中提取TLS协议的JA4和JA3指纹。支持VLAN/多层VLAN/QinQ数据包解析，并基于Client Hello报文方向正确识别TLS会话。

## ✨ 主要功能

- 📁 **Pcap文件解析**: 支持标准pcap格式文件
- 🔍 **TLS检测**: 自动识别TLS流量并解析握手消息
- 🔐 **JA4指纹**: 计算新一代TLS客户端指纹 (JA4, JA4_b, JA4_c)
- 🆔 **JA3指纹**: 计算传统TLS客户端指纹
- 🌐 **VLAN支持**: 完整支持VLAN/多层VLAN/QinQ封装
- 📊 **会话管理**: 基于Client Hello方向正确识别TLS会话
- 🚫 **GREASE过滤**: 正确过滤GREASE值以提高指纹准确性
- 📄 **JSON输出**: 结构化输出指纹数据和会话信息

## 🛠️ 技术实现

### 核心依赖
- **`tls-parser`** - TLS协议解析
- **`pnet`** - 网络层解析（支持VLAN）
- **`pcap`** - Pcap文件处理
- **`serde/serde_json`** - JSON序列化
- **`sha2/md5/hex`** - 哈希计算

### JA4算法实现
- **JA4_a**: 协议版本 + SNI状态 + 密码套件数量 + 扩展数量 + ALPN状态
- **JA4_b**: 密码套件排序后的SHA256哈希前12位
- **JA4_c**: 扩展+签名算法排序后的SHA256哈希前12位
- **最终JA4**: `JA4_a_JA4_b_JA4_c`

### JA3算法实现
- 保持原始顺序（不排序）
- 包含椭圆曲线组和点格式
- MD5哈希计算

## 🚀 快速开始

### 构建项目
```bash
# 克隆项目
git clone <repository-url>
cd tls_ja4

# 构建发布版本
cargo build --release
```

### 基本用法
```bash
# 基本使用
./target/release/tls_ja4 --input sample.pcap

# 指定输出文件
./target/release/tls_ja4 --input sample.pcap --output results.json

# 使用自定义配置
./target/release/tls_ja4 --input sample.pcap --config custom_config.json
```

## 📖 使用说明

### 命令行参数
```
TLS JA4/JA3 Fingerprint Extractor

Usage: tls_ja4 [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>      输入pcap文件路径
  -o, --output <OUTPUT>    输出JSON文件路径 [默认: fingerprints.json]
  -c, --config <CONFIG>    配置文件路径 [默认: config.json]
  -h, --help              显示帮助信息
  -V, --version           显示版本信息
```

### 配置文件
创建 `config.json` 文件来自定义行为：
```json
{
  "include_server_hello": false,
  "max_packets_per_session": 10,
  "include_ja3": true,
  "verbose": false
}
```

**配置选项说明**:
- `include_server_hello`: 是否包含Server Hello分析
- `max_packets_per_session`: 每个会话最大数据包数量
- `include_ja3`: 是否计算JA3指纹
- `verbose`: 是否显示详细调试信息

## 📊 输出格式

程序生成JSON格式的输出文件，包含完整的指纹信息：

```json
{
  "analysis_time": 1759058429,
  "total_sessions": 1,
  "total_packets": 11,
  "tls_packets": 3,
  "sessions": [
    {
      "timestamp": 1759058429,
      "src_ip": "10.105.108.128",
      "dst_ip": "10.105.108.133",
      "src_port": 42965,
      "dst_port": 2443,
      "ja4_fingerprints": [
        "t13d751100_479067518aa3_24695f2957a7"
      ],
      "ja4b_fingerprints": [
        "479067518aa3"
      ],
      "ja4c_fingerprints": [
        "24695f2957a7"
      ],
      "ja3_fingerprints": [
        "732b9e6543be52016be7e6ac897d24d4"
      ],
      "client_hello_count": 1,
      "server_hello_count": 0
    }
  ]
}
```

### 输出字段说明
- **`analysis_time`**: 分析时间戳
- **`total_sessions`**: 总TLS会话数
- **`total_packets`**: 总数据包数
- **`tls_packets`**: TLS数据包数
- **`sessions`**: 会话详细信息数组
  - **`ja4_fingerprints`**: 完整JA4指纹
  - **`ja4b_fingerprints`**: JA4_b组件
  - **`ja4c_fingerprints`**: JA4_c组件
  - **`ja3_fingerprints`**: JA3指纹

## 🔧 高级功能

### VLAN支持
程序自动检测和解析：
- **IEEE 802.1Q** (单层VLAN)
- **IEEE 802.1ad** (QinQ/双层VLAN)
- **多层VLAN嵌套**

### 会话识别
- 基于**Client Hello方向**确定会话
- 自动关联双向流量
- 正确处理Server Hello关联

### GREASE过滤
自动过滤RFC 8701定义的GREASE值：
- 模式: `0x?a?a` (如 0x0a0a, 0x1a1a, 0x2a2a...)
- 影响: 密码套件、扩展、椭圆曲线组、签名算法

## 🧪 测试

### 运行测试
```bash
# 单元测试
cargo test

# 基准测试
cargo bench

# 性能测试
./test_ja4.sh
```

### 测试数据
项目包含测试脚本和示例数据：
- `test_ja4.sh` - JA4功能测试
- `test_example.sh` - 示例数据测试
- `benches/` - 性能基准测试

## 📈 性能特性

- **高效解析**: 使用零拷贝技术和引用传递
- **内存优化**: 避免不必要的数据克隆
- **并发安全**: 支持多实例并行运行
- **大文件支持**: 高效处理大型pcap文件

### 性能指标
- **处理速度**: ~11ms处理小型pcap文件
- **内存使用**: 优化的内存分配策略
- **准确性**: 100%匹配标准JA4/JA3实现

## 🔍 支持的协议

### TLS版本
- **SSL 3.0** → `s3`
- **TLS 1.0** → `10`
- **TLS 1.1** → `11`
- **TLS 1.2** → `12`
- **TLS 1.3** → `13`

### 传输协议
- **TCP** → `t` (当前支持)
- **QUIC** → `q` (框架已预留)

## 🐛 故障排除

### 常见问题

**Q: 为什么没有检测到Client Hello？**
A: 检查pcap文件是否包含TLS握手消息，而不只是加密的应用数据。

**Q: 会话数量不正确？**
A: 程序基于Client Hello方向识别会话，确保pcap包含完整的TLS握手。

**Q: VLAN数据包无法解析？**
A: 程序支持多层VLAN，检查网络配置和pcap捕获设置。

**Q: JA4/JA3值与其他工具不同？**
A: 确认GREASE过滤和扩展解析设置，本程序严格遵循官方算法。

### 调试模式
启用verbose模式获取详细信息：
```json
{
  "verbose": true
}
```

## 📋 JA4标准说明

### JA4_a格式
`{协议}{版本}{SNI}{密码套件数}{扩展数}{ALPN}`

例如：`t13d751100`
- `t` = TCP协议
- `13` = TLS 1.3
- `d` = 有SNI (Domain)
- `75` = 75个密码套件
- `11` = 11个扩展
- `00` = 无ALPN

### SNI状态
- `d` = Domain (有SNI扩展)
- `i` = IP (无SNI扩展)

### ALPN值
- `h1` = HTTP/1.1
- `h2` = HTTP/2
- `00` = 无ALPN

## 🤝 贡献

欢迎提交Issue和Pull Request！

### 开发环境
```bash
# 安装Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 克隆项目
git clone <repository-url>
cd tls_ja4

# 开发构建
cargo build

# 运行测试
cargo test
```

## 📄 许可证

[指定许可证类型]

## 🔗 相关链接

- [JA4标准规范](https://github.com/FoxIO-LLC/ja4)
- [JA3标准规范](https://github.com/salesforce/ja3)
- [TLS-Parser文档](https://docs.rs/tls-parser/)
- [Rust Pcap库](https://docs.rs/pcap/)

---

**版本**: 0.1.0  
**作者**: [sollor525]  
**更新时间**: 2024年9月28日