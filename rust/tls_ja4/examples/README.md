# TLS JA4/JA3 C API 使用示例

本目录包含了TLS JA4/JA3指纹提取库的C语言接口使用示例，展示了从基础功能到高级集成的完整用法。

## 📁 文件结构

```
examples/
├── c_api_basic_example.c      # 基础C API使用示例
├── c_api_advanced_example.c   # 高级C API使用示例（多线程、性能优化）
├── c_api_vpp_integration.c    # VPP集成示例
├── Makefile                   # 示例构建脚本
├── C_API_EXAMPLES.md         # 详细文档
└── README.md                 # 本文件
```

## 🚀 快速开始

### 1. 构建Rust库

```bash
# 在项目根目录构建发布版本
cd ..
cargo build --release
```

### 2. 构建C示例

```bash
# 构建所有示例
make all

# 或者单独构建
make c_api_basic_example
make c_api_advanced_example
make c_api_vpp_integration
```

### 3. 运行示例

```bash
# 运行基础示例
make run-basic

# 运行高级示例
make run-advanced

# 运行VPP集成示例
make run-vpp
```

## 📚 示例说明

### 1. 基础C API示例 (`c_api_basic_example.c`)

**适用场景**: 高性能应用、生产环境、多线程处理

**主要功能**:
- 🚀 多线程并行处理
- 📊 性能基准测试
- 💾 内存管理优化
- 🔧 缓存配置调优
- 📈 性能监控统计

**运行结果示例**:
```
📈 === 多线程 性能统计 ===
  总处理时间: 0.95 ms
  处理数据包数: 1000
  JA3成功数: 1000 (100.0%)
  JA4成功数: 1000 (100.0%)
  处理速度: 1052632 包/秒
  平均处理时间: 0.95 微秒/包

🔄 === 性能对比分析 ===
  多线程加速比: 1.46x
  并行效率: 36.4%
```

### 3. VPP集成示例 (`c_api_vpp_integration.c`)

**适用场景**: VPP网络功能虚拟化、高速数据包处理

**主要功能**:
- 🔗 VPP节点集成
- 🧵 多Worker线程支持
- 📦 批量数据包处理
- 📊 实时性能监控
- 🎯 流表管理

**运行结果示例**:
```
🚀 === VPP节点处理演示 ===
📝 注册节点: tls-ja4-extractor (索引: 0)
✅ 总共处理了 100 个有效的TLS数据包

📊 === TLS JA4节点统计信息 ===
  Worker ID: 0
  运行时间: 0.01 秒
  处理数据包: 100
  提取指纹: 100
  错误数量: 0
  成功率: 100.00%
  处理速度: 9091 包/秒
```

## 🛠️ 构建选项

### 调试版本

```bash
make debug
```

**特点**:
- 包含调试符号
- 禁用优化
- 启用断言检查

### 发布版本

```bash
make release
```

**特点**:
- 优化性能
- 禁用调试信息
- 适合生产环境

### 代码检查

```bash
# 语法检查
make check

# 内存检查（需要valgrind）
make memcheck-basic

# 性能分析（需要perf）
make perf-basic
```

## 📊 性能基准

在Intel i7-8700K (6 cores, 12 threads)上的测试结果：

| 场景 | 数据包数 | 线程数 | 处理时间 | 吞吐量 | 成功率 |
|------|----------|--------|----------|--------|--------|
| 单线程 | 200 | 1 | 0.28ms | 722,022 pps | 100.0% |
| 多线程 | 1000 | 4 | 0.95ms | 1,052,632 pps | 100.0% |
| VPP节点 | 100 | 1 | 11ms | 9,091 pps | 100.0% |

## 🔧 配置说明

### TLS上下文管理

```c
// 初始化上下文
TlsJa4Context* ctx = tls_init();

// 计算JA3指纹
TlsJa3Result ja3_result = {0};
int ret = tls_calculate_ja3(tls_payload, payload_len, &ja3_result);

// 计算JA4指纹
TlsJa4Result ja4_result = {0};
ret = tls_calculate_ja4(tls_payload, payload_len, &ja4_result);

// 清理上下文
tls_cleanup(ctx);
```

### 错误处理

```c
switch (ret) {
    case TLS_JA4_SUCCESS:
        // 处理成功结果
        break;
    case TLS_JA4_NOT_TLS:
        printf("数据不是TLS报文\n");
        break;
    case TLS_JA4_NOT_CLIENT_HELLO:
        printf("TLS报文不是Client Hello\n");
        break;
    default:
        printf("未知错误: %d\n", ret);
        break;
}
```

## 💡 最佳实践

### 1. 多线程设计
- ✅ 每个线程使用独立的TLS上下文
- ✅ 避免共享可变状态
- ✅ 合理设置线程数（通常为CPU核心数）

### 2. 内存管理
- ✅ 及时清理TLS上下文
- ✅ 根据应用场景配置缓存大小
- ✅ 定期清理超时缓存

### 3. 性能优化
- ✅ 批量处理数据包
- ✅ 预检查TLS类型
- ✅ 避免频繁的内存分配

## 🚨 注意事项

1. **当前版本限制**:
   - 暂不支持缓存管理函数
   - 数据库匹配功能为简化版本

2. **兼容性**:
   - 支持Linux系统
   - 需要GCC编译器
   - 需要pthread库

3. **依赖关系**:
   - 需要先构建Rust库
   - 确保libtls_ja4.so在可找到的路径中

## 📖 更多信息

- **详细文档**: 查看 [C_API_EXAMPLES.md](C_API_EXAMPLES.md)
- **API参考**: 查看 [../include/tls_ja4.h](../include/tls_ja4.h)
- **构建系统**: 查看 [Makefile](Makefile)

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这些示例！

### 开发环境设置

```bash
# 安装依赖
sudo apt-get install build-essential valgrind

# 克隆项目
git clone <repository-url>
cd tls_ja4

# 构建和测试
cargo build --release
make all
make run-all
```

## 📄 许可证

本项目遵循MIT或Apache-2.0双重许可证。

---

**🎉 现在就开始使用TLS JA4/JA3 C API吧！**

如有问题，请查看 [C_API_EXAMPLES.md](C_API_EXAMPLES.md) 或提交Issue获取帮助。

## 使用说明

### 基本用法

#### Rust示例
```bash
# 运行基本C API测试
cargo run --example test_new_c_api

# 运行分段TLS处理测试
cargo run --example test_segmented_tls
```

#### C示例
```bash
# 方法1: 使用Makefile（推荐）
cd examples
make          # 构建
make run      # 构建并运行
make clean    # 清理

# 方法2: 使用CMake
cd examples
mkdir build && cd build
cmake ..
make
./vpp_integration_example

# 方法3: 使用构建脚本
cd examples
./build.sh

# 方法4: 手动编译
cd examples
gcc -Wall -Wextra -O2 -std=c99 -I../include -o vpp_integration_example vpp_integration_example.c -L../target/debug -ltls_ja4 -lpthread -ldl -lm
LD_LIBRARY_PATH=../target/debug ./vpp_integration_example
```

### 构建系统

1. **Makefile**: 简化的构建配置，自动处理依赖
2. **CMakeLists.txt**: 完整的CMake配置，支持跨平台
3. **build.sh**: 自动化构建脚本
4. **手动编译**: 直接使用gcc命令

### 注意事项

- 所有示例都是演示性的，实际使用时需要根据具体需求调整
- C API需要正确的内存管理
- VPP集成需要考虑性能优化
- 分段TLS处理需要正确的TCP流重组

## 性能特点

- **零拷贝设计**: 最小化内存分配
- **线程安全**: 无全局状态，适合多线程环境
- **高性能**: 优化的解析算法
- **内存效率**: 智能缓存管理

## 集成指南

### VPP集成步骤

1. 将库编译为静态库
2. 在VPP节点中包含头文件
3. 初始化上下文
4. 在数据包处理循环中调用分析函数
5. 处理结果和错误情况
6. 清理资源

### 错误处理

- 检查返回值
- 处理分段情况
- 管理内存生命周期
- 处理异常情况

## 更多信息

详细的API文档请参考主项目的README.md文件。
