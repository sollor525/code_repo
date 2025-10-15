# Makefile for JA4 Fingerprint Demo (Simple Version)
# 用于构建JA4指纹计算演示程序（简化版本）

# 基本设置
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g -O2
TARGET = ja4_simple_demo
SRC = ja4_simple_demo.c

# Rust库路径（相对于项目根目录）
RUST_LIB_DIR = ../../../target/release
RUST_LIB_NAME = libtls_ja4.so

# 默认目标
all: build-rust-lib $(TARGET)

# 构建Rust库
build-rust-lib:
	@echo "构建Rust JA4库..."
	cd ../../../ && cargo build --release
	@echo "Rust库构建完成"

# 编译C程序
$(TARGET): $(SRC) $(RUST_LIB_DIR)/$(RUST_LIB_NAME)
	@echo "编译JA4演示程序（简化版本）..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -L$(RUST_LIB_DIR) -ltls_ja4 -Wl,-rpath,$(RUST_LIB_DIR) -ldl -lpthread
	@echo "编译完成"

# 运行程序
run: $(TARGET)
	@echo "运行JA4指纹演示程序（简化版本）..."
	./$(TARGET)

# 调试版本
debug: CFLAGS += -DDEBUG -O0 -g3
debug: build-rust-debug-lib $(TARGET)

# 构建调试版Rust库
build-rust-debug-lib:
	cd ../../ && cargo build

# 优化版本
release: CFLAGS += -DNDEBUG -O3 -march=native
release: clean build-rust-lib $(TARGET)

# 清理生成的文件
clean:
	@echo "清理生成的文件..."
	rm -f $(TARGET) *.o ja4_c_demo_output.txt

# 测试程序功能
test: $(TARGET)
	@echo "运行JA4功能测试..."
	./$(TARGET) > ja4_c_demo_output.txt 2>&1
	@echo "测试输出已保存到 ja4_c_demo_output.txt"

# 快速测试（只运行，不保存输出）
quick-test: $(TARGET)
	./$(TARGET)

# 验证C API可用性
verify-api:
	@echo "验证C API可用性..."
	nm -D $(RUST_LIB_DIR)/$(RUST_LIB_NAME) | grep tls_ja4 || echo "⚠️  可能需要检查C API导出"

# 性能测试
benchmark: $(TARGET)
	@echo "运行性能基准测试..."
	time ./$(TARGET)

# 检查依赖
check-deps:
	@echo "检查构建依赖..."
	@which gcc > /dev/null || (echo "❌ 需要安装gcc" && exit 1)
	@which cargo > /dev/null || (echo "❌ 需要安装Rust和Cargo" && exit 1)
	@echo "✅ 所有依赖已满足"

# 显示程序信息
info:
	@echo "JA4简化演示程序信息:"
	@echo "===================="
	@echo "目标程序: $(TARGET)"
	@echo "源文件: $(SRC)"
	@echo "编译器: $(CC)"
	@echo "编译选项: $(CFLAGS)"
	@echo "Rust库路径: $(RUST_LIB_DIR)"

# 帮助信息
help:
	@echo "JA4指纹演示程序 Makefile（简化版本）"
	@echo "====================================="
	@echo ""
	@echo "可用目标:"
	@echo "  all         - 构建Rust库和C程序（默认）"
	@echo "  build-rust-lib - 仅构建Rust库"
	@echo "  $(TARGET)      - 编译C程序"
	@echo "  run         - 编译并运行程序"
	@echo "  quick-test   - 快速测试程序"
	@echo "  test        - 运行功能测试并保存输出"
	@echo "  debug       - 构建调试版本"
	@echo "  release     - 构建优化版本"
	@echo "  benchmark   - 运行性能基准测试"
	@echo "  verify-api  - 验证C API导出"
	@echo "  check-deps  - 检查构建依赖"
	@echo "  info        - 显示程序信息"
	@echo "  clean       - 清理生成的文件"
	@echo "  help        - 显示此帮助信息"
	@echo ""
	@echo "示例用法:"
	@echo "  make              # 构建所有组件"
	@echo "  make run          # 构建并运行"
	@echo "  make quick-test   # 快速测试"
	@echo "  make test         # 完整测试"

# 声明伪目标
.PHONY: all build-rust-lib run debug release clean test quick-test verify-api benchmark check-deps info help build-rust-debug-lib

# 默认目标
.DEFAULT_GOAL := all