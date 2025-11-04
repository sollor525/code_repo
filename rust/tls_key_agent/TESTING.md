# TLS Key Agent 测试指南

本文档介绍如何使用TLS Key Agent的测试功能来验证TLS密钥提取是否正常工作。

## 概述

TLS Key Agent提供了多种测试方式来验证TLS密钥提取功能：

1. **集成测试** - 端到端测试TLS密钥提取
2. **示例程序** - 演示如何使用TLS Key Agent
3. **验证工具** - 分析和验证密钥日志文件

## 前置条件

### 系统要求
- Linux操作系统
- Rust 1.70+
- OpenSSL开发库
- gcc编译器（用于构建C Hook库）

### 安装依赖
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential libssl-dev pkg-config

# CentOS/RHEL
sudo yum install gcc gcc-c++ openssl-devel pkgconfig

# 或者在Fedora上
sudo dnf install gcc gcc-c++ openssl-devel pkgconfig
```

## 构建项目

```bash
# 克隆项目
git clone <repository-url>
cd tls_key_agent

# 构建所有组件
cargo build --release

# 或者包含测试功能
cargo build --features test-utils
```

## 测试方法

### 1. 运行集成测试

```bash
# 运行所有集成测试
cargo test --test test_baidu_integration --features test-utils

# 运行特定测试
cargo test test_baidu_tls_key_extraction --features test-utils
```

### 2. 运行示例程序

```bash
# 运行百度测试示例
cargo run --example baidu_test --features test-utils

# 或者先构建再运行
cargo build --example baidu_test --features test-utils
./target/debug/examples/baidu_test
```

示例程序会：
- 检查运行环境
- 创建和启动TLS Key Agent
- 设置LD_PRELOAD环境变量
- 执行多种测试场景（curl、原生HTTPS、多次连接）
- 分析和显示密钥提取结果

### 3. 使用验证工具

验证工具提供了多种功能来分析密钥日志文件：

#### 分析密钥日志文件
```bash
# 分析默认密钥日志文件
cargo run --bin verify_keys -- analyze

# 分析指定文件
cargo run --bin verify_keys -- analyze --file /path/to/keys.log

# 显示详细信息
cargo run --bin verify_keys -- analyze --verbose
```

#### 实时监控密钥日志
```bash
# 监控密钥日志文件（60秒超时）
cargo run --bin verify_keys -- monitor

# 自定义超时时间
cargo run --bin verify_keys -- monitor --timeout 120
```

#### 验证密钥文件格式
```bash
# 验证密钥日志文件格式
cargo run --bin verify_keys -- validate --check-format

# 验证指定文件
cargo run --bin verify_keys -- validate --file /path/to/keys.log
```

#### 显示统计信息
```bash
# 显示密钥统计信息
cargo run --bin verify_keys -- stats

# 以JSON格式输出
cargo run --bin verify_keys -- stats --json
```

#### 测试TLS连接
```bash
# 测试百度TLS连接
cargo run --bin verify_keys -- test

# 测试自定义主机
cargo run --bin verify_keys -- test --host example.com --port 443
```

## 手动测试步骤

### 1. 准备环境

```bash
# 设置密钥日志文件路径
export SSLKEYLOGFILE="/tmp/tls_test.log"

# 构建Hook库
cargo build
```

### 2. 启动TLS Key Agent

```bash
# 在一个终端中启动Agent
cargo run --features test-utils
```

### 3. 设置LD_PRELOAD并测试

```bash
# 在另一个终端中设置LD_PRELOAD
export LD_PRELOAD="./target/debug/libtls_key_agent_hook.so"

# 使用curl测试
curl -s https://www.baidu.com > /dev/null

# 或者使用wget
wget -q -O - https://www.baidu.com > /dev/null

# 或者使用openssl命令
echo "GET / HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n" | openssl s_client -connect www.baidu.com:443 -quiet
```

### 4. 检查结果

```bash
# 查看密钥日志文件
cat $SSLKEYLOGFILE

# 使用验证工具分析
cargo run --bin verify_keys -- analyze --file $SSLKEYLOGFILE
```

## 预期结果

### 成功的密钥提取

如果一切正常，你应该能看到类似这样的输出：

```
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 1699123456 # SSL_connect
```

其中：
- `CLIENT_RANDOM` 表示这是一个Client Random和Master Secret对
- 第一个64字符的十六进制字符串是Client Random（32字节）
- 第二个96字符的十六进制字符串是Master Secret（48字节）
- 最后是时间戳和操作信息

### 验证工具输出

验证工具会显示详细的分析结果：

```
╔══════════════════════════════════════════════════════════════╗
║                      密钥分析结果                              ║
╚══════════════════════════════════════════════════════════════╝

📊 基本统计:
  - 总记录数: 5
  - Client Random记录: 3
  - 唯一Client Random数: 3
  - 记录时间跨度: 15 秒

🔍 密钥质量分析:
  - 高熵值密钥: 3
  - 低熵值密钥: 0

🎉 成功提取到 3 个TLS密钥！
```

## 故障排除

### 常见问题

#### 1. Hook库未加载
**症状**: 没有密钥被提取，密钥日志文件为空

**解决方案**:
```bash
# 检查Hook库是否存在
ls -la ./target/debug/libtls_key_agent_hook.so

# 检查LD_PRELOAD是否正确设置
echo $LD_PRELOAD

# 检查库依赖
ldd ./target/debug/libtls_key_agent_hook.so
```

#### 2. 权限不足
**症状**: 程序运行但没有权限设置LD_PRELOAD

**解决方案**:
```bash
# 尝试以root权限运行
sudo -E LD_PRELOAD=./target/debug/libtls_key_agent_hook.so curl https://www.baidu.com
```

#### 3. OpenSSL版本兼容性问题
**症状**: Hook库加载但无法提取密钥

**解决方案**:
```bash
# 检查OpenSSL版本
openssl version

# 检查系统使用的OpenSSL库
ldd $(which curl) | grep ssl
```

#### 4. 编译错误
**症状**: 构建过程中出现编译错误

**解决方案**:
```bash
# 更新Rust工具链
rustup update

# 清理并重新构建
cargo clean
cargo build --features test-utils

# 检查依赖
sudo apt-get install build-essential libssl-dev pkg-config
```

### 调试技巧

#### 启用详细日志
```bash
# 设置RUST_LOG环境变量
export RUST_LOG=debug

# 运行程序
cargo run --example baidu_test --features test-utils
```

#### 检查Hook函数调用
```bash
# 使用strace跟踪系统调用
strace -e openat,write curl https://www.baidu.com

# 检查库加载
LD_DEBUG=libs curl https://www.baidu.com
```

#### 手动验证Hook库
```bash
# 使用nm检查符号
nm -D ./target/debug/libtls_key_agent_hook.so | grep SSL

# 检查库依赖
readelf -d ./target/debug/libtls_key_agent_hook.so
```

## 性能测试

### 批量连接测试
```bash
# 使用示例程序进行多次连接测试
cargo run --example baidu_test --features test-utils

# 或者使用脚本
for i in {1..10}; do
    echo "测试连接 $i"
    curl -s https://www.baidu.com > /dev/null
    sleep 0.1
done
```

### 监控资源使用
```bash
# 监控内存使用
watch -n 1 'ps aux | grep tls_key_agent'

# 监控文件描述符
lsof -p $(pgrep tls_key_agent)
```

## 贡献测试用例

如果你想为项目贡献新的测试用例：

1. 在`tests/`目录下添加新的测试文件
2. 在`examples/`目录下添加新的示例程序
3. 更新本文档说明新的测试方法
4. 确保所有测试都能通过

```bash
# 运行所有测试
cargo test --features test-utils

# 运行所有示例
cargo test --examples --features test-utils
```

## 相关文档

- [TLS Key Agent 主要文档](README.md)
- [API文档](docs/api.md)
- [部署指南](docs/deployment.md)
- [故障排除指南](docs/troubleshooting.md)