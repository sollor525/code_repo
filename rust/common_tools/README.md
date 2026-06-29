# 开发辅助工具 Development Assistance Tool

一款面向网络协议调试的**桌面工具集**，基于 [Tauri 2](https://v2.tauri.app/) +
Rust 构建。原生窗口内嵌一个 [axum](https://github.com/tokio-rs/axum) 服务承载界面与
API，前端为重新设计的「示波器 / 协议分析仪」风格 UI。前端资源在编译期嵌入二进制，
最终产物是**单文件、自包含**的可执行程序。

## 功能特性

| 工具 | 说明 |
|------|------|
| 🛰 网络转换 | IP / 端口 / 整数在主机序与网络序之间互转，支持十进制与十六进制 |
| 📦 报文分析 | 解析 Hex 报文，逐层拆出以太网 / IP / TCP·UDP·ICMP 头部，并可导出 PCAP |
| 🧪 PCAP 生成 | 按参数合成多协议流量并导出 PCAP：TCP（仅SYN/三次握手/四次挥手/RST）、HTTP（可自定义请求/响应）、ICMP、UDP、FTP（主动/被动）、SSH、MySQL；支持 IPv4 / IPv6、VLAN / QinQ、按 MTU 自动 TCP 分段 / IP 分片、可指定载荷大小自动填充；可下载或保存到指定目录 |
| 🔎 正则匹配 | 实时匹配与捕获组展示，支持大小写、多行、点号匹配换行等选项 |
| 🔐 MD5 计算 | 计算文本或文件的 MD5 摘要，用于校验与完整性比对 |
| 🔁 字符串转换 | 八进制（`\000`）与 Unicode（`\u0000`）转义序列双向转换，自动识别格式 |

## 架构

桌面版采用「内嵌服务」模式：应用启动时在后台线程内拉起 axum 服务，绑定
`127.0.0.1` 上的一个随机空闲端口，再打开指向它的 Tauri WebView 窗口。因此现有的
HTML/CSS/JS 前端与 `fetch('/api/...')` 调用**无需改动**即可在桌面外壳中运行。

```
common_tools/
├── static/                     # 前端（Tauri frontendDist）
├── genpcap/                    # PCAP 生成核心子 crate（自 rust/gen_pcap 移植的纯 Rust 报文生成）
└── src-tauri/                  # Rust 工程（Tauri 约定布局）
    ├── tauri.conf.json         # productName=Development Assistance Tool, identifier=com.bytebench.commontools
    ├── build.rs · capabilities/ · icons/
    └── src/
        ├── main.rs             # 入口：desktop（Tauri 窗口）/ server（纯服务）双模式
        ├── server.rs           # axum 路由 + 处理器 + include_str! 嵌入的静态资源
        ├── web_api.rs          # /api/* 处理器与统一 ApiResponse 包装
        └── network_utils.rs · packet_analyzer.rs · pcap_generator.rs · regex_matcher.rs · md5_utils.rs · string_converter.rs
```

`main.rs` 通过 Cargo `desktop` 特性选择入口：

- **桌面模式（默认）** —— Tauri 窗口 + 内嵌服务，用于打包 Windows 桌面应用。
- **服务模式（`--no-default-features`）** —— 不依赖 Tauri / WebView 的纯 axum 服务，
  可在任意平台编译运行，用于验证逻辑或无界面部署。

## 快速开始

### 桌面版（Windows）

需要 Windows 10/11 + Rust(MSVC) + C++ Build Tools + WebView2 运行时，详见
[`BUILD_WINDOWS.md`](BUILD_WINDOWS.md)。

```powershell
cd src-tauri
cargo build --release          # 便携版：target\release\common_tools.exe（自包含）
# 或生成安装包：
cargo install tauri-cli --version "^2"
cargo tauri build              # → ...\bundle\nsis\Development Assistance Tool_0.1.0_x64-setup.exe
```

> Tauri 不支持从 Linux/macOS 交叉编译 Windows 版本，请在 Windows 上构建。

开发调试（带窗口热重载）：

```powershell
cargo tauri dev
```

### 服务模式（任意平台，无需 WebView）

```bash
cd src-tauri
cargo build --no-default-features
CT_PORT=3030 ./target/debug/common_tools     # 端口取自 CT_PORT，未设置则自动分配
# 浏览器打开 http://127.0.0.1:3030
```

二进制已内嵌全部前端资源，可从任意目录运行，无需随附 `static/`。

### 测试

```bash
cd src-tauri
cargo test --no-default-features
```

## API

内嵌服务暴露以下接口（请求/响应均为 JSON，统一包装为
`{ success, data, error, timestamp }`）：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/health` | 健康检查 |
| GET  | `/api` | 服务与端点信息 |
| POST | `/api/network/convert` | 网络序转换 |
| POST | `/api/packet/analyze` | 报文分析 |
| POST | `/api/packet/download` | 导出 PCAP（字节流下载） |
| POST | `/api/packet/export` | 导出 PCAP 到运行目录 |
| POST | `/api/pcap/generate` | 生成多协议流量 PCAP（JSON 请求，返回 .pcap 附件） |
| POST | `/api/pcap/download` | 表单方式下载 PCAP（隐藏 `<form>` 提交，附件响应触发原生下载，兼容 WebView） |
| POST | `/api/pcap/save` | 生成并保存到目录（默认程序当前目录），返回文件名与路径 |
| POST | `/api/regex/match` | 正则匹配 |
| POST | `/api/md5/calculate` | 文本 MD5 计算 |
| POST | `/api/md5/calculate_file` | 文件 MD5 计算（上传文件字节，按内容求值） |
| POST | `/api/string/convert` | 字符串转义转换 |

示例：

```bash
curl -X POST http://127.0.0.1:3030/api/network/convert \
  -H 'Content-Type: application/json' \
  -d '{"value":"192.168.1.1","conversion_type":"ip_to_network"}'
# {"success":true,"data":{"input":"192.168.1.1","result":"0xC0A80101", ... }, ...}
```

接口字段细节见 [`static/API.md`](static/API.md)。

## 技术栈

- **桌面外壳**：Tauri 2（WebView2 / WebKitGTK）
- **内嵌服务**：axum 0.7 + Tokio
- **序列化**：serde / serde_json
- **工具实现**：regex、md5、pcap-file、hex（均为纯 Rust）
- **PCAP 生成**：`genpcap` 子 crate（pnet_packet / pnet_base / rand，纯 Rust，不依赖 libpcap）

## 相关文档

- [`BUILD_WINDOWS.md`](BUILD_WINDOWS.md) —— Windows 桌面版构建步骤
- [`DEPLOYMENT.md`](DEPLOYMENT.md) —— 分发与部署（桌面分发 / 无界面服务）
- [`CLAUDE.md`](CLAUDE.md) —— 面向 AI 助手的架构与约定说明

## 许可证

MIT
