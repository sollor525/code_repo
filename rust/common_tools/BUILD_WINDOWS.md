# Building the Windows desktop app (Tauri)

`common_tools` is now a **Tauri v2** desktop application. The native window
(WebView2) loads an axum web server that is started inside the same process and
bound to `127.0.0.1` on a random free port. All frontend assets (HTML/CSS/JS)
are **embedded into the binary** at compile time, so the resulting `.exe` is
self-contained — no `static/` folder needs to ship next to it.

> Tauri does not support cross-compiling Windows builds from Linux, so build this
> on a Windows machine. (The repo was scaffolded and the embedded server was
> verified on Linux via the non-Tauri `server` build — see the bottom section.)

## Prerequisites (Windows 10 / 11)

1. **Rust** (MSVC toolchain) — install from <https://rustup.rs>. Accept the
   default `stable-x86_64-pc-windows-msvc`.
2. **Microsoft C++ Build Tools** — the "Desktop development with C++" workload
   (MSVC compiler + Windows SDK). rustup links you to it during setup.
3. **WebView2 Runtime** — preinstalled on Windows 11 and current Windows 10.
   If missing, install the Evergreen runtime from Microsoft.
4. **Tauri CLI** (only needed to produce an installer):
   ```powershell
   cargo install tauri-cli --version "^2"
   ```

## Build

From the project root (`...\rust\common_tools`):

### Option A — portable single executable (simplest)
```powershell
cd src-tauri
cargo build --release
# → src-tauri\target\release\common_tools.exe
```
Double-click `common_tools.exe`: it starts the embedded server and opens the
native window. It needs only the WebView2 runtime; everything else is embedded.

### Option B — installer (.exe via NSIS)
```powershell
# from the project root
cargo tauri build
# → src-tauri\target\release\bundle\nsis\ByteBench_0.1.0_x64-setup.exe
# (the portable exe is also produced at src-tauri\target\release\common_tools.exe)
```

### Develop with hot window reload
```powershell
cargo tauri dev
```

## How it's wired

- `src-tauri/src/main.rs` — desktop entry: spawns the axum server on a background
  Tokio runtime (`127.0.0.1:0`), then opens a `WebviewWindow` pointing at the
  resolved `http://127.0.0.1:<port>`. The existing frontend's `fetch('/api/...')`
  calls keep working unchanged because the server is right there.
- `src-tauri/src/server.rs` — the axum router + handlers, with all of `static/`
  embedded via `include_str!`.
- `static/` — the frontend (set as `frontendDist` in `tauri.conf.json`).
- `src-tauri/tauri.conf.json` — Tauri config (productName **ByteBench**,
  identifier `com.bytebench.commontools`, bundle target `nsis`).
- `src-tauri/icons/` — app icons (`icon.ico` is used for the Windows build).

## Verifying the server logic without Tauri (any OS)

The shared server/tool logic builds without the Tauri/WebView dependency, which
is how it was checked on the Linux build host:
```bash
cd src-tauri
cargo build --no-default-features          # compiles everything except Tauri
CT_PORT=3031 ./target/debug/common_tools   # runs the embedded server headless
# then open http://127.0.0.1:3031
```
