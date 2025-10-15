# JA4 C Demos Collection

本目录包含了TLS JA4项目的所有C语言演示程序，专注于JA4指纹计算和C API的使用。每个demo都在独立的子目录中，并配有自己的Makefile。

## 📁 目录结构

### JA4应用程序Demo

#### 1. ja4_fingerprint
- **描述**: JA4指纹计算演示程序（完整版本）
- **功能**: 全面的JA4/JA3指纹计算测试，包含性能测试、错误处理等
- **特点**: 依赖Rust JA4库，功能完整
- **构建**: `make -C ja4_fingerprint all`
- **运行**: `make -C ja4_fingerprint run`

#### 2. ja4_simple
- **描述**: JA4指纹计算演示程序（简化版本）
- **功能**: 简化的JA4指纹计算测试，易于理解和修改
- **特点**: 依赖Rust JA4库，代码简洁
- **构建**: `make -C ja4_simple all`
- **运行**: `make -C ja4_simple run`

### C API测试程序

#### 3. test_c_api
- **描述**: 基础C API测试
- **功能**: 测试C API的基本功能
- **构建**: `make -f Makefile.test_c_api all`
- **运行**: `make -f Makefile.test_c_api run`

#### 4. test_c_api_comprehensive
- **描述**: 综合C API测试
- **功能**: 全面的C API功能测试
- **构建**: `make -f Makefile.test_c_api_comprehensive all`
- **运行**: `make -f Makefile.test_c_api_comprehensive run`

#### 5. vpp_integration
- **描述**: VPP集成示例
- **功能**: 演示如何在VPP中集成JA4指纹计算
- **构建**: `make -f Makefile.vpp_integration all`
- **运行**: `make -f Makefile.vpp_integration run`

## 🚀 快速开始

### 1. 使用总Makefile（推荐）

```bash
# 进入examples目录
cd examples

# 查看快速开始指南
make quickstart

# 检查依赖
make check-deps

# 构建Rust库（JA4 demo需要）
make build-rust-lib

# 构建所有demo
make build-all

# 测试JA4功能
make test-ja4

# 查看所有可用demo
make list-demos
```

### 2. 单独构建特定demo

```bash
# 构建JA4简化版本
make -C c_demos/ja4_simple all

# 构建JA4完整版本
make -C c_demos/ja4_fingerprint all

# 构建基础C API测试
make -C c_demos -f Makefile.test_c_api all
```

### 3. 运行特定demo

```bash
# 运行JA4简化版本
make -C c_demos/ja4_simple quick-test

# 运行JA4完整版本
make -C c_demos/ja4_fingerprint run

# 运行基础C API测试
make -C c_demos -f Makefile.test_c_api run
```

## 📋 依赖要求

### 系统依赖
- **gcc**: C编译器
- **make**: 构建工具
- **cargo**: Rust包管理器

### 库依赖
- **libtls_ja4.so**: TLS JA4 Rust库（所有JA4 demo都需要）

## 🛠️ 构建选项

每个demo都支持以下常见的Makefile目标：

- `all` - 构建程序（默认）
- `run` - 构建并运行程序
- `debug` - 构建调试版本
- `release` - 构建优化版本
- `clean` - 清理生成的文件
- `help` - 显示帮助信息

JA4相关的demo还支持：
- `test` - 运行功能测试
- `quick-test` - 快速测试程序
- `benchmark` - 运行性能测试
- `verify-api` - 验证C API导出

## 📊 构建状态

查看所有demo的构建状态：

```bash
make status
```

## 🧹 清理

清理所有demo：

```bash
make clean-all
```

## 📚 详细文档

每个demo目录中都有详细的文档和注释：

- **ja4_fingerprint/**: JA4指纹计算的完整实现和测试
- **ja4_simple/**: 简化的JA4示例，适合学习和快速验证
- **C API测试程序**: 展示如何在实际项目中使用JA4 C API

## 🔍 故障排除

### 常见问题

1. **找不到Rust库**
   ```bash
   make build-rust-lib
   ```

2. **编译错误**
   ```bash
   make check-deps
   ```

3. **运行时错误**
   ```bash
   # 检查库路径
   export LD_LIBRARY_PATH=$PWD/../target/release:$LD_LIBRARY_PATH
   ```

### 调试技巧

- 使用调试版本：`make debug`
- 查看详细输出：`make run 2>&1 | tee output.log`
- 检查依赖：`make check-deps`

## 🎯 使用建议

### 学习JA4指纹计算
- 从 `ja4_simple` 开始，理解基本概念
- 然后查看 `ja4_fingerprint` 了解完整功能

### 集成到项目
- 参考 `test_c_api` 了解基本API使用
- 查看 `vpp_integration` 了解实际集成示例

### 性能优化
- 使用 `benchmark` 目标测试性能
- 参考 `release` 构建的优化设置

## 🤝 贡献

欢迎为这些demo贡献代码！请确保：

1. 代码风格一致
2. 添加适当的注释
3. 更新相关文档
4. 测试所有功能

## 📄 许可证

这些demo程序遵循项目的主许可证条款。