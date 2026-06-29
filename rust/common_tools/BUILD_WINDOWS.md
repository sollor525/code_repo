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
2. **Microsoft C++ Build Tools** — the **"Desktop development with C++"** workload
   (MSVC `link.exe`/`cl.exe` + Windows SDK). Install via the **Visual Studio
   Installer** (standalone Build Tools *or* full VS → Modify → tick that workload).
   The Visual Studio IDE on its own is **not** enough — that workload is what
   provides the linker; without it you get `error: linker 'link.exe' not found`.
3. **WebView2 Runtime** — preinstalled on Windows 11 and current Windows 10.
   If missing, install the Evergreen runtime from Microsoft.
4. **Tauri CLI** (only needed to produce an installer):
   ```powershell
   cargo install tauri-cli --version "^2"
   ```

## Build

> **Build from a Visual Studio developer shell — not Git Bash, and not a plain
> PowerShell/cmd.** MSVC's linker is only on `PATH` inside the VS environment.
> Use any one of:
> - the **"x64 Native Tools Command Prompt for VS"** (Start menu), or
> - a `cmd` window after running `"...\VC\Auxiliary\Build\vcvars64.bat"`, or
> - PowerShell after `& "...\Common7\Tools\Launch-VsDevShell.ps1" -Arch amd64`
>   (the leading `&` is required; `vcvars64.bat` does **not** work in PowerShell).
>
> Git Bash / MSYS2 will fail: its `link.exe` is GNU coreutils, not MSVC's.
> Sanity check inside the shell: `where link` must point at `…\VC\Tools\MSVC\…`.

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
# → src-tauri\target\release\bundle\nsis\Development Assistance Tool_0.1.0_x64-setup.exe
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
- `src-tauri/tauri.conf.json` — Tauri config (productName **Development Assistance Tool**,
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

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `error: linker 'link.exe' not found` | MSVC C++ workload not installed (the VS IDE alone is not enough), or you're in a shell without the VS env. Install **"Desktop development with C++"** and build from a VS developer shell. |
| `link: extra operand … Try 'link --help'` | You're in **Git Bash / MSYS2** — its GNU `link.exe` shadows MSVC's. Build from the VS dev shell / x64 Native Tools prompt instead. |
| `proc macro panicked … Unsupported PNG bit depth: Sixteen` | An icon is a 16-bit PNG; Tauri's `generate_context!` needs 8-bit. Regenerate every icon + `.ico` frame at 8-bit (ImageMagick: `-depth 8` / `PNG32:`). The committed icons are already 8-bit. |
| Builds, but the window is blank or won't open | Install the **WebView2 runtime** (Evergreen) — required at runtime, not build time. |
| `cargo install tauri-cli` fails to link | Same shell issue — run it from the VS dev shell, not Git Bash. |
