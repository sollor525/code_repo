# 字节工具台 部署与分发指南

本项目现为 **Tauri 桌面应用**。主要交付物是一个 Windows 桌面程序；同时保留了一个
不依赖 WebView 的**服务模式**，可用于无界面/服务器部署。本文覆盖两种场景的分发方式。

- [一、桌面版分发（Windows）](#一桌面版分发windows)
- [二、无界面服务模式部署](#二无界面服务模式部署)
- [三、容器化服务模式（可选）](#三容器化服务模式可选)
- [四、故障排除](#四故障排除)

> 构建步骤本身见 [`BUILD_WINDOWS.md`](BUILD_WINDOWS.md)。本文聚焦「构建产物如何分发与运行」。

---

## 一、桌面版分发（Windows）

`cargo tauri build` / `cargo build --release` 会产出两类制品：

| 制品 | 路径 | 用途 |
|------|------|------|
| 便携版可执行文件 | `src-tauri\target\release\common_tools.exe` | 免安装，直接双击运行 |
| NSIS 安装包 | `src-tauri\target\release\bundle\nsis\ByteBench_0.1.0_x64-setup.exe` | 标准安装流程，写入开始菜单/卸载项 |

应用名（窗口标题/开始菜单）为 **字节工具台 / ByteBench**，应用标识为
`com.bytebench.commontools`。

### 运行依赖

- **WebView2 运行时**：Windows 11 与较新的 Windows 10 已内置；若缺失，安装微软
  [Evergreen WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)。
  这是桌面版唯一的外部运行依赖——前端资源与服务逻辑都已编译进 exe，**无需**随附
  `static/` 目录或任何 DLL（MSVC 运行库随 exe 静态/系统提供）。

### 分发方式

- **便携分发**：直接把 `common_tools.exe` 发给用户即可，双击启动后会在本机
  `127.0.0.1` 的随机空闲端口拉起内嵌服务，并打开原生窗口。
- **安装包分发**：分发 `ByteBench_*-setup.exe`，提供安装/卸载体验，适合面向终端用户。

### 代码签名（可选，建议用于对外分发）

未签名的 exe/安装包在用户机器上可能触发 SmartScreen 警告。如需消除：

- 使用代码签名证书对 exe 与安装包签名（`signtool sign /fd SHA256 ...`）。
- Tauri 也支持在打包阶段自动签名，配置 `tauri.conf.json` 的
  `bundle.windows.certificateThumbprint` 等字段。

### 自动更新（可选，当前未启用）

Tauri 内置 updater 插件可实现增量自动更新。如需启用，需添加
`@tauri-apps/plugin-updater`、配置更新服务器与签名公钥；当前项目未集成。

---

## 二、无界面服务模式部署

服务模式是不含 Tauri/WebView 的纯 axum 服务，适合放在服务器上以浏览器访问。它同样
**自包含**（前端已嵌入二进制）。

### 构建与运行

```bash
cd src-tauri
cargo build --release --no-default-features        # 产物：target/release/common_tools
CT_PORT=8080 ./target/release/common_tools         # 端口取自 CT_PORT，未设置则自动分配
```

- 监听地址固定为 **`127.0.0.1`**（仅本机）。`CT_PORT` 控制端口。
- 二进制可放在任意目录运行，无需 `static/`。

### 对外暴露

由于服务仅监听 `127.0.0.1`，对外提供时请在前面加一层反向代理：

```nginx
server {
    listen 80;
    server_name your-domain.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

如确需直接对外监听 `0.0.0.0`，请在 `src-tauri/src/main.rs` 的服务模式入口中调整
`TcpListener::bind` 的地址（当前硬编码为 `127.0.0.1`）。

### systemd 守护

```ini
[Unit]
Description=ByteBench 服务模式
After=network.target

[Service]
Type=simple
Environment=CT_PORT=8080
ExecStart=/opt/bytebench/common_tools
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp common_tools /opt/bytebench/
sudo cp bytebench.service /etc/systemd/system/
sudo systemctl enable --now bytebench
```

---

## 三、容器化服务模式（可选）

> 旧版（Tauri 改造前）的 `Dockerfile`、`docker-compose.yml`、`docker-deploy.sh`、
> `deploy.sh`、`build_release.sh` 已随本次重构**删除**——它们假设代码与 `Cargo.toml`
> 位于仓库根目录并从磁盘读取 `static/`，这些前提均已不再成立。

如需容器化服务模式，工程现位于 `src-tauri/`，构建需加 `--no-default-features`，且无需
再拷贝 `static/`（资源已内嵌）。最小 Dockerfile 示例：

```dockerfile
FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
RUN cd src-tauri && cargo build --release --no-default-features
FROM debian:bookworm-slim
COPY --from=build /app/src-tauri/target/release/common_tools /usr/local/bin/
ENV CT_PORT=8080
EXPOSE 8080
CMD ["common_tools"]
```

> 注意：服务监听 `127.0.0.1`，容器内对外暴露时仍需将其改为 `0.0.0.0` 或加反代。

---

## 四、故障排除

| 现象 | 排查 |
|------|------|
| 双击 exe 无窗口/闪退 | 确认已安装 WebView2 运行时；用 `cargo build` 的调试版可见控制台日志 |
| Windows 提示「无法验证发布者」 | 未签名所致，见 [代码签名](#代码签名可选建议用于对外分发) |
| 交叉编译 Windows 失败 | Tauri 不支持从 Linux/macOS 交叉编译 Windows，请在 Windows 上构建 |
| 服务模式外网访问不到 | 默认仅监听 `127.0.0.1`，需反向代理或改绑定地址 |
| 端口被占用（服务模式） | 改用其他 `CT_PORT`，或不设置该变量以自动分配空闲端口 |
