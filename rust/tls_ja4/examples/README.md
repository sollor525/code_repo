# TLS JA4/JA3 Examples

这个目录包含了TLS JA4/JA3指纹提取库的使用示例。

## 文件说明

### Rust示例

#### `test_new_c_api.rs`
- **用途**: 演示C API的基本使用方法
- **功能**: 
  - 测试完整IP数据包处理（包含IP头+TCP头+TLS载荷）
  - 测试TLS数据包检测
  - 测试Client Hello检测
  - 演示完整的分析流程和指纹计算
- **运行**: `cargo run --example test_new_c_api`
- **输出示例**: 
  ```
  Is TLS packet: -2
  Is Client Hello: -3
  ✅ Success!
  JA4: t120d20h0_0_37effddb63e8_0
  JA3: af236ae680d7741a172c340dbd5ca7dacff8e684d303b57a60c2ca142ef9a017
  ```

#### `test_segmented_tls.rs`
- **用途**: 演示真正的分段TLS处理功能
- **功能**:
  - 模拟TLS Client Hello被分割成3个TCP分段
  - 演示分段缓存和重组机制
  - 展示完整的指纹计算流程
  - 演示上下文管理和错误处理
- **运行**: `cargo run --example test_segmented_tls`
- **输出示例**:
  ```
  📦 Processing Segment 1 (90 bytes)...
  📦 Segment 1 cached, waiting for more data...
  📦 Processing Segment 2 (44 bytes)...
  📦 Segment 2 cached, waiting for more data...
  📦 Processing Segment 3 (66 bytes)...
  ✅ Complete TLS Client Hello assembled from segments!
  JA4: t120d20h0_0_37effddb63e8_0
  JA3: af236ae680d7741a172c340dbd5ca7dacff8e684d303b57a60c2ca142ef9a017
  ```
- **特点**: 真实展示VPP环境中可能遇到的分段TLS处理场景

### C示例

#### `vpp_integration_example.c`
- **用途**: 完整的VPP集成示例
- **功能**:
  - 展示如何在VPP节点中集成TLS指纹提取
  - 演示IP包构建和分析
  - 展示便捷函数的使用
  - **新增**: 真正的分段TLS处理演示
  - 提供完整的VPP集成指南
- **编译**: 需要链接libtls_ja4库
- **演示内容**:
  - Method 1: 简单TLS检测和分析
  - Method 2: 支持分段的处理
  - **Method 3: 真正的分段TLS处理** (新增)
- **特点**:
  - 线程安全设计
  - 零拷贝原则
  - 高性能处理
  - 支持分段TLS处理
  - 真实的分段重组演示

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
