# TLS JA4 Examples Makefile
# 简化的构建配置

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS = -lpthread -ldl -lm

# 路径配置
RUST_TARGET_DIR = ../target/debug
RUST_LIB = $(RUST_TARGET_DIR)/libtls_ja4.so
INCLUDE_DIR = ../include
HEADER = $(INCLUDE_DIR)/tls_ja4.h

# 目标文件
TARGET = vpp_integration_example
SOURCE = vpp_integration_example.c

# 默认目标
all: $(TARGET)

# 检查依赖
check-deps:
	@echo "🔍 Checking dependencies..."
	@if [ ! -f "$(RUST_LIB)" ]; then \
		echo "📦 Building Rust library..."; \
		cd .. && cargo build; \
	fi
	@if [ ! -f "$(HEADER)" ]; then \
		echo "❌ Error: Header file not found at $(HEADER)"; \
		exit 1; \
	fi

# 构建C示例
$(TARGET): check-deps $(SOURCE)
	@echo "🔨 Building $(TARGET)..."
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -o $(TARGET) $(SOURCE) -L$(RUST_TARGET_DIR) -ltls_ja4 $(LDFLAGS)
	@echo "✅ Build completed successfully!"

# 运行示例
run: $(TARGET)
	@echo "🚀 Running $(TARGET)..."
	LD_LIBRARY_PATH=$(RUST_TARGET_DIR) ./$(TARGET)

# 清理
clean:
	@echo "🧹 Cleaning..."
	rm -f $(TARGET)
	@echo "✅ Clean completed!"

# 完全清理（包括Rust构建）
clean-all: clean
	@echo "🧹 Cleaning Rust build..."
	cd .. && cargo clean

# 帮助信息
help:
	@echo "TLS JA4 Examples Build System"
	@echo "============================="
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build the C example (default)"
	@echo "  run        - Build and run the example"
	@echo "  clean      - Remove built files"
	@echo "  clean-all  - Remove all build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make        # Build the example"
	@echo "  make run    # Build and run"
	@echo "  make clean  # Clean up"

.PHONY: all check-deps run clean clean-all help
