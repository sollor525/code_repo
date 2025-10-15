# Examples Makefile for TLS JA4 Project
# 管理所有示例程序的构建和运行

# 项目设置
PROJECT_ROOT = ..
RUST_LIB_DIR = $(PROJECT_ROOT)/target/release

# JA4 Demo目录列表
JA4_DEMOS = c_demos/ja4_fingerprint \
           c_demos/ja4_simple

# C API测试程序
C_API_TESTS = c_demos/test_c_api \
             c_demos/test_c_api_comprehensive \
             c_demos/vpp_integration

# 所有demo目录
ALL_DEMOS = $(JA4_DEMOS) $(C_API_TESTS)

# 默认目标：显示帮助信息
.DEFAULT_GOAL := help

# 构建所有JA4 demos
build-ja4-demos:
	@echo "构建所有JA4 demo程序..."
	@for demo in $(JA4_DEMOS); do \
		echo "构建 $$demo..."; \
		$(MAKE) -C $$demo all || exit 1; \
		echo "✅ $$demo 构建完成"; \
	done
	@echo "🎉 所有JA4 demo构建完成！"

# 构建所有C API测试程序
build-c-api-tests:
	@echo "构建所有C API测试程序..."
	@for test in $(C_API_TESTS); do \
		echo "构建 $$test..."; \
		$(MAKE) -C c_demos -f Makefile.$(shell basename $$test) all || exit 1; \
		echo "✅ $$test 构建完成"; \
	done
	@echo "🎉 所有C API测试程序构建完成！"

# 构建所有demo
build-all: build-ja4-demos build-c-api-tests
	@echo "🎉 所有demo程序构建完成！"

# 运行所有JA4 demos
run-ja4-demos:
	@echo "运行所有JA4 demo程序..."
	@for demo in $(JA4_DEMOS); do \
		echo "运行 $$demo..."; \
		$(MAKE) -C $$demo run || echo "⚠️  $$demo 运行可能需要交互"; \
		echo ""; \
	done
	@echo "🎉 所有JA4 demo运行完成！"

# 运行所有C API测试程序
run-c-api-tests:
	@echo "运行所有C API测试程序..."
	@for test in $(C_API_TESTS); do \
		echo "运行 $$test..."; \
		$(MAKE) -C c_demos -f Makefile.$(shell basename $$test) run || echo "⚠️  $$test 运行可能有问题"; \
		echo ""; \
	done
	@echo "🎉 所有C API测试程序运行完成！"

# 运行所有demo
run-all: run-ja4-demos run-c-api-tests
	@echo "🎉 所有demo程序运行完成！"

# 测试JA4指纹计算功能
test-ja4:
	@echo "测试JA4指纹计算功能..."
	@echo "1. 测试简化版本..."
	$(MAKE) -C c_demos/ja4_simple quick-test || exit 1
	@echo "2. 测试完整版本..."
	$(MAKE) -C c_demos/ja4_fingerprint test || exit 1
	@echo "🎉 JA4指纹计算测试完成！"

# 构建Rust库（所有JA4 demo依赖）
build-rust-lib:
	@echo "构建Rust JA4库..."
	cd $(PROJECT_ROOT) && cargo build --release
	@echo "✅ Rust库构建完成"

# 清理所有demo
clean-all:
	@echo "清理所有demo..."
	@for demo in $(ALL_DEMOS); do \
		echo "清理 $$demo..."; \
		if [ -f $$demo/Makefile ]; then \
			$(MAKE) -C $$demo clean 2>/dev/null || true; \
		fi; \
		if [ -f $$demo/../Makefile.$(shell basename $$demo) ]; then \
			$(MAKE) -C $$demo/.. -f Makefile.$(shell basename $$demo) clean 2>/dev/null || true; \
		fi; \
	done
	@echo "🎉 所有demo清理完成！"

# 检查依赖
check-deps:
	@echo "检查构建依赖..."
	@which gcc > /dev/null || (echo "❌ 需要安装gcc" && exit 1)
	@which cargo > /dev/null || (echo "❌ 需要安装Rust和Cargo" && exit 1)
	@which make > /dev/null || (echo "❌ 需要安装make" && exit 1)
	@echo "✅ 所有依赖已满足"

# 列出所有可用的demo
list-demos:
	@echo "可用的JA4 Demo程序:"
	@echo "==================="
	@for demo in $(JA4_DEMOS); do \
		echo "📁 $$demo"; \
		if [ -f $$demo/Makefile ]; then \
			echo "   可用命令: make -C $$demo {build,run,clean,help}"; \
		fi; \
	done
	@echo ""
	@echo "可用的C API测试程序:"
	@echo "==================="
	@for test in $(C_API_TESTS); do \
		echo "📁 $$test"; \
		echo "   可用命令: make -C c_demos -f Makefile.$(shell basename $$test) {build,run,clean}"; \
	done

# 构建状态报告
status:
	@echo "构建状态报告"
	@echo "============="
	@echo ""
	@echo "Rust库状态:"
	@if [ -f $(RUST_LIB_DIR)/libtls_ja4.so ]; then \
		echo "✅ Rust库已构建: $(RUST_LIB_DIR)/libtls_ja4.so"; \
	else \
		echo "❌ Rust库未构建"; \
	fi
	@echo ""
	@echo "JA4 Demo状态:"
	@for demo in $(JA4_DEMOS); do \
		if [ -f $$demo/Makefile ]; then \
			target=$$(grep "^TARGET *=" $$demo/Makefile | awk '{print $$3}'); \
			if [ -f $$demo/$$target ]; then \
				echo "✅ $$demo ($$target) - 已构建"; \
			else \
				echo "❌ $$demo ($$target) - 未构建"; \
			fi; \
		fi; \
	done
	@echo ""
	@echo "C API测试状态:"
	@for test in $(C_API_TESTS); do \
		if [ -f c_demos/Makefile.$(shell basename $$test) ]; then \
			target=$$(grep "^TARGET *=" c_demos/Makefile.$(shell basename $$test) | awk '{print $$3}'); \
			if [ -f c_demos/$$target ]; then \
				echo "✅ $$test ($$target) - 已构建"; \
			else \
				echo "❌ $$test ($$target) - 未构建"; \
			fi; \
		fi; \
	done

# 快速开始指南
quickstart:
	@echo "TLS JA4 Demo 快速开始指南"
	@echo "========================"
	@echo ""
	@echo "1. 检查依赖:"
	@echo "   make check-deps"
	@echo ""
	@echo "2. 构建Rust库:"
	@echo "   make build-rust-lib"
	@echo ""
	@echo "3. 构建所有demo:"
	@echo "   make build-all"
	@echo ""
	@echo "4. 测试JA4功能:"
	@echo "   make test-ja4"
	@echo ""
	@echo "5. 查看所有可用demo:"
	@echo "   make list-demos"

# 帮助信息
help:
	@echo "TLS JA4 Examples Makefile"
	@echo "========================="
	@echo ""
	@echo "主要命令:"
	@echo "---------"
	@echo "  help                    - 显示此帮助信息（默认）"
	@echo "  quickstart             - 显示快速开始指南"
	@echo "  check-deps             - 检查构建依赖"
	@echo "  status                 - 显示构建状态"
	@echo "  list-demos             - 列出所有可用demo"
	@echo ""
	@echo "构建命令:"
	@echo "---------"
	@echo "  build-rust-lib         - 仅构建Rust库"
	@echo "  build-ja4-demos        - 构建所有JA4 demo程序"
	@echo "  build-c-api-tests      - 构建所有C API测试程序"
	@echo "  build-all              - 构建所有demo"
	@echo ""
	@echo "运行命令:"
	@echo "---------"
	@echo "  run-ja4-demos          - 运行所有JA4 demo程序"
	@echo "  run-c-api-tests        - 运行所有C API测试程序"
	@echo "  run-all                - 运行所有demo"
	@echo ""
	@echo "测试命令:"
	@echo "---------"
	@echo "  test-ja4               - 测试JA4指纹计算功能"
	@echo ""
	@echo "维护命令:"
	@echo "---------"
	@echo "  clean-all              - 清理所有demo"
	@echo ""
	@echo "示例用法:"
	@echo "---------"
	@echo "  make quickstart         # 查看快速开始指南"
	@echo "  make build-all          # 构建所有demo"
	@echo "  make test-ja4           # 测试JA4功能"
	@echo ""
	@echo "单独运行特定demo:"
	@echo "------------------"
	@echo "  make -C c_demos/ja4_simple run"
	@echo "  make -C c_demos/ja4_fingerprint run"
	@echo "  make -C c_demos -f Makefile.test_c_api run"

# 声明伪目标
.PHONY: build-ja4-demos build-c-api-tests build-all run-ja4-demos run-c-api-tests run-all test-ja4 build-rust-lib clean-all check-deps list-demos status quickstart help