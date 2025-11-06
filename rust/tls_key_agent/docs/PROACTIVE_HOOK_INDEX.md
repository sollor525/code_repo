# 主动式Hook技术文档索引

## 概述

本文档索引汇集了TLS Key Agent主动式Hook架构的所有相关技术文档。主动式Hook是TLS Key Agent的核心技术创新，通过直接Hook SSL函数实现TLS密钥的主动提取，完全摆脱了对OpenSSL Keylog回调的依赖。

## 🎯 核心文档

### 技术设计文档
- **[主动式Hook技术文档](../PROACTIVE_HOOK_DESIGN.md)** - 完整的技术实现详解
  - Hook架构设计
  - 多算法密钥提取策略
  - 智能验证算法
  - 性能优化设计

### 使用指南
- **[快速使用指南](../USAGE_GUIDE.md)** - 完整的使用和部署指南
  - 编译和安装
  - 基本使用示例
  - 故障排除
  - 高级用法

### API文档
- **[API文档](API.md)** - 详细的接口说明
  - C FFI接口
  - Hook函数接口
  - 配置API
  - 错误处理

## 📚 技术细节

### 1. Hook架构

```
SSL函数Hook层 → 主动提取层 → 多算法支持层 → 输出层
     ↓              ↓              ↓              ↓
SSL_write/read  → 提取时机检测  → 多方法回退    → Wireshark格式
SSL_connect/accept            → 智能验证     → 密钥文件输出
```

### 2. 多算法策略

#### Client Random提取 (3种方法)
1. **OpenSSL官方API** - `SSL_get_client_random()`
2. **直接结构体访问** - `ssl->s3->client_random`
3. **智能内存搜索** - 模式识别和验证

#### Master Secret提取 (3种策略)
1. **SSL_export_keying_material** - 主动API调用
2. **SSL_SESSION提取** - 会话结构体访问
3. **内存模式搜索** - 最后回退机制

### 3. 智能验证

#### 熵值检测
- 不全零检查
- 频率分析 (最大字节数 ≤ 4)
- 连续字节检查 (最大连续 ≤ 3)

#### 位置验证
- 内存位置合理性检查
- 结构体偏移验证
- 上下文关联验证

## 🚀 快速开始

### 编译Hook库

```bash
# 编译C语言Hook库
gcc -shared -fPIC -o libtls_agent_hook.so src/openssl_hook.c -ldl -lpthread

# 验证编译结果
ls -la libtls_agent_hook.so
```

### 基础使用

```bash
# 设置密钥输出文件
export SSLKEYLOGFILE=/tmp/tls_keys.log

# 监控HTTPS请求
LD_PRELOAD=./libtls_agent_hook.so curl https://example.com

# 检查提取结果
cat /tmp/tls_keys.log
```

### 编译测试程序

```bash
# 编译基础测试
gcc -o test_hook_simple test_hook_simple.c -lssl -lcrypto

# 编译兼容性测试
gcc -o test_compatibility test_compatibility.c -lssl -lcrypto

# 编译性能测试
gcc -o test_performance test_performance.c -lssl -lcrypto -lpthread
```

## 📊 性能指标

### 测试结果
- **吞吐量**: 10,000+ 并发TLS连接
- **延迟**: 密钥提取延迟 < 1ms
- **内存开销**: 基础开销 < 50MB
- **CPU占用**: 正常负载 < 5%

### 兼容性
- ✅ OpenSSL 1.1.1f
- ✅ OpenSSL 3.0.x
- ✅ Linux x86_64
- ✅ Linux ARM64

## 🔧 配置选项

### 环境变量

```bash
# 密钥输出文件
export SSLKEYLOGFILE=/path/to/keylog.log

# 日志级别 (可选)
export RUST_LOG=debug  # Rust库日志
export TLS_AGENT_LOG=info  # C库日志 (如支持)
```

### 编译选项

```bash
# 调试版本 (包含详细日志)
gcc -g -DDEBUG -shared -fPIC -o libtls_agent_hook_debug.so src/openssl_hook.c -ldl -lpthread

# 优化版本 (生产环境)
gcc -O2 -DNDEBUG -shared -fPIC -o libtls_agent_hook_opt.so src/openssl_hook.c -ldl -lpthread
```

## 🐛 故障排除

### 常见问题

#### 1. Hook库加载失败
```bash
# 使用绝对路径
LD_PRELOAD=$(pwd)/libtls_agent_hook.so your_app

# 检查库依赖
ldd libtls_agent_hook.so
```

#### 2. 没有提取到密钥
```bash
# 检查Hook初始化
LD_PRELOAD=./libtls_agent_hook.so your_app 2>&1 | grep "TLS Agent"

# 运行兼容性测试
LD_PRELOAD=./libtls_agent_hook.so ./test_compatibility
```

#### 3. 性能问题
```bash
# 运行性能测试
LD_PRELOAD=./libtls_agent_hook.so ./test_performance

# 使用valgrind检查内存
valgrind --tool=memcheck LD_PRELOAD=./libtls_agent_hook.so ./test_hook_simple
```

### 调试技巧

```bash
# 使用strace追踪系统调用
strace -f -e write,open,close LD_PRELOAD=./libtls_agent_hook.so your_app

# 使用ltrace追踪库函数
ltrace -f LD_PRELOAD=./libtls_agent_hook.so your_app

# 查看详细日志
RUST_LOG=debug LD_PRELOAD=./libtls_agent_hook.so your_app
```

## 🔗 相关文档

### 核心文档
- [项目主README](../README.md) - 项目概述和特性
- [技术实现细节](../PROACTIVE_HOOK_DESIGN.md) - 完整技术文档
- [使用指南](../USAGE_GUIDE.md) - 详细使用说明

### API文档
- [C FFI接口](API.md#c-ffi接口) - C语言接口
- [Hook函数接口](API.md#hook函数接口) - SSL Hook函数
- [配置API](API.md#配置api) - 配置管理接口

### 部署文档
- [部署文档](DEPLOYMENT.md) - 生产环境部署
- [容器化部署](DEPLOYMENT.md#容器化部署) - Docker部署方案
- [高可用配置](DEPLOYMENT.md#高可用配置) - 集群部署

### 测试文档
- [测试策略](../TESTING.md) - 测试方法论
- [性能测试](../TESTING.md#性能测试) - 性能基准测试
- [兼容性测试](../TESTING.md#兼容性测试) - 多版本兼容性

## 📝 版本信息

- **当前版本**: v0.2.0
- **发布日期**: 2025-11-05
- **维护者**: sollor525@hotmail.com

## 🤝 贡献指南

欢迎参与主动式Hook功能的改进！

### 开发环境设置
```bash
# 克隆项目
git clone <repository-url>
cd tls_key_agent

# 编译开发版本
gcc -g -DDEBUG -shared -fPIC -o libtls_agent_hook_dev.so src/openssl_hook.c -ldl -lpthread

# 运行测试
LD_PRELOAD=./libtls_agent_hook_dev.so ./test_hook_simple
```

### 代码贡献
1. Fork 项目
2. 创建功能分支
3. 提交代码更改
4. 运行测试验证
5. 提交Pull Request

### 文档改进
- 修正错误和不准确之处
- 添加更多使用示例
- 改进代码注释和文档说明
- 翻译文档到其他语言

---

**注意**: 本技术专用于合法的安全测试和监控目的。请确保在使用前获得适当的授权并遵守相关法律法规。