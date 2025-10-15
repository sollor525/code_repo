# 通用工具集 Web API

一个基于 Rust 和 Warp 框架开发的高性能 Web 服务，提供网络序转换、报文分析和正则表达式匹配功能的 RESTful API。包含美观的 Web 界面和强大的 API 服务。

## 功能特性

### 🔧 网络序转换 API
- IP地址转换（IPv4/IPv6 与十六进制格式互转）
- 端口转换（主机序与网络序互转）
- 整数转换（32位/64位整数主机序与网络序互转）

### 📦 报文分析 API
- Hex数据解析
- 网络协议分析（以太网、IP、TCP/UDP）
- PCAP文件导出

### 🔍 正则表达式匹配 API
- 正则表达式匹配和捕获
- 支持大小写敏感/不敏感匹配
- 多行模式
- 点号匹配所有字符模式

## 🚀 快速开始

### 安装依赖

只需要安装 Rust，无需任何系统 GUI 库依赖：

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### 构建和运行

1. 克隆项目
   ```bash
   git clone <repository-url>
   cd common_tools
   ```

2. 构建项目
   ```bash
   cargo build --release
   ```

3. 运行服务器
   ```bash
   # 使用默认配置 (127.0.0.1:3030)
   cargo run

   # 或者自定义配置
   cargo run -- --host 0.0.0.0 --port 8080
   ```

4. 访问 Web 界面
   ```
   浏览器打开: http://localhost:3030
   ```

### Docker 部署

```bash
# 构建镜像
docker build -t common-tools .

# 运行容器
docker run -p 3030:3030 common-tools
```

## 🌐 Web 界面功能

### 🏠 主页
- 项目介绍和特性展示
- 快速导航到各功能页面
- API 使用示例和技术栈说明
- 响应式设计，支持移动端

### 🌐 网络序转换页面
- **IP地址转换**: IPv4/IPv6 与十六进制格式互转
- **端口转换**: 主机序与网络序互转
- **整数转换**: 32位/64位整数转换
- **实时转换**: 输入即可看到结果
- **格式支持**: 十进制、十六进制格式

### 📦 报文分析页面
- **Hex数据解析**: 支持多种格式输入
- **协议分析**: 以太网、IP、TCP/UDP、ICMP
- **示例数据**: 内置TCP、UDP、ICMP示例
- **PCAP导出**: 一键导出标准PCAP文件
- **拖拽支持**: 支持拖拽文本文件

### 🔍 正则匹配页面
- **实时匹配**: 输入即可看到匹配结果
- **高级选项**: 大小写敏感、多行模式、点号匹配所有字符
- **内置示例**: 邮箱、电话、URL、IP地址常用正则
- **捕获组显示**: 显示所有捕获组和位置信息
- **一键使用**: 快速使用常用正则表达式

### 🎨 界面特色
- **现代设计**: 渐变背景、卡片布局、动画效果
- **响应式布局**: 支持桌面、平板、手机
- **暗色主题**: 自动适配系统主题
- **交互友好**: 实时反馈、快捷键支持

## API 文档

### 基础信息

- **基础URL**: `http://localhost:3030`
- **Content-Type**: `application/json`
- **所有响应都包含时间戳和标准错误格式**

### 端点概览

| 方法 | 端点 | 描述 |
|------|------|------|
| GET | `/` | API 信息 |
| GET | `/health` | 健康检查 |
| POST | `/api/network/convert` | 网络序转换 |
| POST | `/api/packet/analyze` | 报文分析 |
| POST | `/api/packet/export` | 导出 PCAP |
| POST | `/api/regex/match` | 正则匹配 |

### API 使用示例

#### 1. 网络序转换

**IPv4 转网络序:**
```bash
curl -X POST http://localhost:3030/api/network/convert \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.168.1.1",
    "conversion_type": "ip_to_network"
  }'
```

**端口转换:**
```bash
curl -X POST http://localhost:3030/api/network/convert \
  -H "Content-Type: application/json" \
  -d '{
    "value": "8080",
    "conversion_type": "port_to_network"
  }'
```

#### 2. 报文分析

**分析 Hex 数据:**
```bash
curl -X POST http://localhost:3030/api/packet/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "hex_data": "08002712345608002712345608000450000283c7c4000400643c2c0a80101c0a801c8"
  }'
```

#### 3. 正则表达式匹配

**正则匹配:**
```bash
curl -X POST http://localhost:3030/api/regex/match \
  -H "Content-Type: application/json" \
  -d '{
    "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
    "test_string": "Contact us at support@example.com or admin@test.org",
    "case_sensitive": false,
    "multi_line": false,
    "dot_all": false
  }'
```

### 响应格式

所有 API 响应都遵循统一格式：

```json
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": "2023-12-01T10:30:00Z"
}
```

错误响应：
```json
{
  "success": false,
  "data": null,
  "error": "错误描述",
  "timestamp": "2023-12-01T10:30:00Z"
}
```

## 项目结构

```
common_tools/
├── src/
│   ├── main.rs              # Web 服务器入口
│   ├── web_api.rs           # API 路由和处理逻辑
│   ├── network_utils.rs     # 网络序转换功能
│   ├── packet_analyzer.rs   # 报文分析功能
│   └── regex_matcher.rs     # 正则匹配功能
├── static/                  # 前端静态文件
│   ├── index.html           # 主页
│   ├── network.html         # 网络序转换页面
│   ├── packet.html          # 报文分析页面
│   ├── regex.html           # 正则匹配页面
│   ├── style.css            # 统一样式文件
│   └── API.md               # API 详细文档
├── Cargo.toml               # 项目依赖配置
├── Dockerfile               # Docker 部署文件
└── README.md                # 项目说明文档
```

## 技术栈

- **Web框架**: Warp (高性能异步 HTTP 服务器)
- **异步运行时**: Tokio
- **序列化**: Serde + JSON
- **正则表达式**: Rust 标准库 regex
- **网络处理**: pnet, pcap-file
- **数据转换**: byteorder, hex
- **日志**: env_logger, log

## 性能特性

- 🚀 **高性能**: 基于 Tokio 异步运行时，支持高并发
- 💾 **低内存**: Rust 零成本抽象，内存使用效率高
- 🛡️ **类型安全**: 编译时类型检查，避免运行时错误
- 🔒 **线程安全**: 所有功能都是线程安全的
- 📈 **可扩展**: 易于添加新的工具和 API 端点

## 配置选项

| 环境变量 | 默认值 | 描述 |
|----------|--------|------|
| `RUST_LOG` | `info` | 日志级别 (error/warn/info/debug/trace) |
| `HOST` | `127.0.0.1` | 服务器绑定地址 |
| `PORT` | `3030` | 服务器监听端口 |

## 命令行选项

```bash
common_tools [OPTIONS]

OPTIONS:
    -h, --host <HOST>     服务器绑定地址 [default: 127.0.0.1]
    -p, --port <PORT>     服务器监听端口 [default: 3030]
        --help            显示帮助信息
        --version         显示版本信息
```

## 部署建议

### 生产环境

1. **使用反向代理** (Nginx/Apache)
2. **启用 HTTPS**
3. **设置适当的 CORS 策略**
4. **配置日志轮转**
5. **设置资源限制**

### Nginx 配置示例

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:3030;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## 许可证

本项目采用 MIT 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目！

### 开发指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 更新日志

### v0.1.0
- ✨ **Web 界面**: 美观的现代化前端界面
- 🚀 **完整功能**: 网络序转换、报文分析、正则匹配
- 🎨 **响应式设计**: 支持桌面、平板、手机
- 🌙 **暗色主题**: 自动适配系统主题
- ⚡ **实时反馈**: 输入即可看到结果
- 📱 **移动端友好**: 优化的移动端体验
- 🔧 **快捷键支持**: 提高操作效率
- 📊 **示例数据**: 内置丰富的示例
- 💾 **数据导出**: 支持PCAP文件导出
- 🛡️ **类型安全**: Rust 内存安全保证
- 🐳 **Docker支持**: 容器化部署
- 📚 **完整文档**: 详细的使用说明和API文档