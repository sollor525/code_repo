# 编译和构建指南

本文档说明如何编译和构建 Web Scan Rust 库，生成可供 C 程序调用的共享库（.so 文件）。

## 版本信息

- **当前版本**: v0.1.0
- **测试状态**: 65/65 测试通过 (100%)
- **构建状态**: 生产就绪

## 目录

- [系统要求](#系统要求)
- [安装依赖](#安装依赖)
- [快速构建](#快速构建)
- [详细构建步骤](#详细构建步骤)
- [构建产物](#构建产物)
- [构建选项](#构建选项)
- [Hyperscan集成](#hyperscan集成)
- [测试验证](#测试验证)
- [常见问题](#常见问题)

## 系统要求

### 必需组件

- **Rust 工具链**: 1.70 或更高版本
- **Cargo**: Rust 包管理器（随 Rust 一起安装）
- **C 编译器**: GCC 或 Clang（用于编译 C 示例程序）
- **Make**: 用于运行 Makefile（可选）

### 操作系统支持

- Linux (推荐)
- macOS
- Windows (需要额外配置)

## 安装依赖

### 1. 安装 Rust

```bash
# 使用官方安装脚本（推荐）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 激活 Rust 环境
source ~/.cargo/env

# 验证安装
rustc --version
cargo --version
```

### 2. 安装 Hyperscan（可选但推荐）

Hyperscan 是 Intel 的高性能正则表达式引擎，可以显著提升匹配性能。

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install libhyperscan-dev
```

#### CentOS/RHEL

```bash
sudo yum install hyperscan-devel
# 或对于较新版本
sudo dnf install hyperscan-devel
```

#### macOS

```bash
brew install hyperscan
```

#### 从源码编译（高级用户）

```bash
git clone https://github.com/intel/hyperscan.git
cd hyperscan
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

### 3. 安装 cbindgen（用于生成 C 头文件）

```bash
cargo install cbindgen
```

## 构建步骤

### 方法 1: 使用 Makefile（推荐）

```bash
# 进入项目目录
cd web_scan_rust

# 构建发布版本（启用 Hyperscan）
make release

# 构建调试版本
make debug

# 运行测试
make test

# 清理构建产物
make clean
```

### 方法 2: 使用 Cargo 直接构建

```bash
# 进入项目目录
cd web_scan_rust

# 构建发布版本（启用 Hyperscan）
cargo build --release --features hyperscan

# 构建调试版本
cargo build --features hyperscan

# 运行测试
cargo test --features hyperscan

# 运行集成测试（单线程模式）
cargo test --test integration_tests --features hyperscan -- --test-threads=1
```

### 方法 3: 不启用 Hyperscan 构建

```bash
# 构建发布版本（不使用 Hyperscan）
cargo build --release

# 构建调试版本
cargo build
```

## 构建产物

构建完成后，会在以下位置生成文件：

### 动态库文件

- **Linux**: `target/release/libweb_scan_rust.so`
- **macOS**: `target/release/libweb_scan_rust.dylib`
- **Windows**: `target/release/web_scan_rust.dll`

### C 头文件

- `include/web_scan_rust.h` - C 语言头文件（如果使用 cbindgen 生成）

### 静态库（可选）

- `target/release/libweb_scan_rust.rlib` - Rust 静态库

## 构建选项

### 启用/禁用 Hyperscan

在 `Cargo.toml` 中，Hyperscan 支持通过 feature flag 控制：

```toml
[features]
default = ["hyperscan"]
hyperscan = ["hyperscan-rs"]
```

**启用 Hyperscan**（默认）：
```bash
cargo build --release --features hyperscan
```

**禁用 Hyperscan**：
```bash
cargo build --release --no-default-features
```

### 优化选项

#### 发布模式优化

发布模式（`--release`）会自动启用以下优化：

- 代码优化（`-O3` 级别）
- 去除调试信息
- 链接时优化（如果启用）

#### 链接时优化（LTO）

在 `Cargo.toml` 中启用：

```toml
[profile.release]
lto = true
codegen-units = 1
```

然后构建：
```bash
cargo build --release --features hyperscan
```

**注意**：LTO 会显著增加编译时间，但可以提升运行时性能。

### 目标架构

#### 交叉编译

```bash
# 安装目标架构工具链
rustup target add x86_64-unknown-linux-gnu

# 构建指定架构
cargo build --release --target x86_64-unknown-linux-gnu --features hyperscan
```

#### 32 位构建

```bash
# 安装 32 位工具链
rustup target add i686-unknown-linux-gnu

# 构建 32 位版本
cargo build --release --target i686-unknown-linux-gnu --features hyperscan
```

## 验证构建

### 1. 检查库文件

```bash
# 检查库文件是否存在
ls -lh target/release/libweb_scan_rust.so

# 检查库依赖
ldd target/release/libweb_scan_rust.so

# 检查库中的符号
nm -D target/release/libweb_scan_rust.so | grep web_scan
```

### 2. 运行测试

```bash
# 运行所有测试
cargo test --features hyperscan

# 运行集成测试
cargo test --test integration_tests --features hyperscan -- --test-threads=1

# 运行特定测试
cargo test --test integration_tests test_multiple_content_cross_packet --features hyperscan
```

### 3. 编译并运行 C 示例

```bash
# 编译 C 示例程序
gcc -o example examples/c_integration.c -Ltarget/release -lweb_scan_rust -Iinclude -ldl

# 设置库路径
export LD_LIBRARY_PATH=target/release:$LD_LIBRARY_PATH

# 运行示例
./example
```

## 常见问题

### 1. 找不到 Hyperscan 库

**错误信息**：
```
error: failed to run custom build command for `hyperscan-sys`
```

**解决方案**：

```bash
# 检查 Hyperscan 是否安装
pkg-config --modversion hyperscan

# 如果未安装，安装 Hyperscan 开发包
# Ubuntu/Debian:
sudo apt-get install libhyperscan-dev

# 设置库路径（如果安装在非标准位置）
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```

### 2. 链接错误

**错误信息**：
```
undefined reference to `hyperscan_*`
```

**解决方案**：

确保在构建时启用了 Hyperscan feature：
```bash
cargo build --release --features hyperscan
```

### 3. 运行时找不到库

**错误信息**：
```
error while loading shared libraries: libweb_scan_rust.so: cannot open shared object file
```

**解决方案**：

```bash
# 方法 1: 设置 LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/web_scan_rust/target/release:$LD_LIBRARY_PATH

# 方法 2: 将库复制到系统库目录
sudo cp target/release/libweb_scan_rust.so /usr/local/lib/
sudo ldconfig

# 方法 3: 使用 rpath（在编译 C 程序时）
gcc -o program program.c -Ltarget/release -lweb_scan_rust -Wl,-rpath,target/release
```

### 4. 头文件找不到

**错误信息**：
```
fatal error: web_scan_rust.h: No such file or directory
```

**解决方案**：

```bash
# 确保头文件存在
ls include/web_scan_rust.h

# 编译时指定头文件路径
gcc -o program program.c -Iinclude -Ltarget/release -lweb_scan_rust
```

### 5. 编译时间过长

**原因**：启用 LTO 或首次编译需要下载依赖

**解决方案**：

```bash
# 禁用 LTO（在 Cargo.toml 中）
[profile.release]
lto = false

# 使用国内镜像加速（可选）
# 在 ~/.cargo/config 中添加：
[source.crates-io]
replace-with = 'ustc'

[source.ustc]
registry = "https://mirrors.ustc.edu.cn/crates.io-index"
```

### 6. 内存不足

**错误信息**：
```
error: failed to allocate memory
```

**解决方案**：

```bash
# 增加交换空间
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# 或减少并行编译任务
cargo build --release --jobs 1
```

## 性能优化建议

### 1. 使用发布模式

始终使用 `--release` 标志构建生产版本：

```bash
cargo build --release --features hyperscan
```

### 2. 启用 LTO

对于生产环境，启用链接时优化：

```toml
[profile.release]
lto = true
codegen-units = 1
```

### 3. 优化代码生成单元

减少代码生成单元数量可以提高优化效果：

```toml
[profile.release]
codegen-units = 1
```

### 4. 使用 CPU 特定优化

```bash
# 针对特定 CPU 优化
RUSTFLAGS="-C target-cpu=native" cargo build --release --features hyperscan
```

## 持续集成（CI）

### GitHub Actions 示例

```yaml
name: Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Install Hyperscan
        run: |
          sudo apt-get update
          sudo apt-get install -y libhyperscan-dev
      - name: Build
        run: cargo build --release --features hyperscan
      - name: Test
        run: cargo test --features hyperscan
```

## 总结

构建 Web Scan Rust 库的基本步骤：

1. 安装 Rust 工具链
2. 安装 Hyperscan（可选但推荐）
3. 运行 `cargo build --release --features hyperscan`
4. 验证构建产物
5. 运行测试确保功能正常

如果遇到问题，请参考常见问题部分或查看项目文档。

