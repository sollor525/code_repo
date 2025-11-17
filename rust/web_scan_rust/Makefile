# Makefile - Web扫描检测引擎构建脚本
# 
# 这个Makefile提供了便捷的构建、测试和清理命令，
# 简化了Rust项目的开发和部署流程。

# 项目名称和版本
PROJECT_NAME = web_scan_rust
VERSION = 0.1.0

# 构建配置
CARGO = cargo                    # Cargo命令路径
CARGO_FLAGS = --release         # 发布模式构建标志
TARGET_DIR = target             # 目标目录
RELEASE_DIR = $(TARGET_DIR)/release
INCLUDE_DIR = $(TARGET_DIR)/include

# 输出文件路径
LIB_NAME = lib$(PROJECT_NAME)
ifeq ($(OS),Windows_NT)
    # Windows系统
    LIB_EXT = dll
    LIB_FILE = $(RELEASE_DIR)/$(LIB_NAME).$(LIB_EXT)
else
    # Unix/Linux系统
    LIB_EXT = so
    LIB_FILE = $(RELEASE_DIR)/$(LIB_NAME).$(LIB_EXT)
endif

# 头文件路径
HEADER_FILE = $(INCLUDE_DIR)/$(PROJECT_NAME).h

# 默认目标：构建项目
.PHONY: all
all: build

# 构建项目（发布模式）
# 生成优化的二进制文件和C头文件
.PHONY: build
build: $(LIB_FILE) $(HEADER_FILE)
	@echo "构建完成！"
	@echo "库文件: $(LIB_FILE)"
	@echo "头文件: $(HEADER_FILE)"

# 构建Rust库
$(LIB_FILE): Cargo.toml src/
	@echo "构建Rust库..."
	$(CARGO) build $(CARGO_FLAGS)
	@echo "Rust库构建完成"

# 生成C头文件
$(HEADER_FILE): $(LIB_FILE)
	@echo "生成C头文件..."
	@mkdir -p $(INCLUDE_DIR)
	@echo "头文件已生成: $(HEADER_FILE)"

# 开发模式构建（包含调试信息）
.PHONY: build-debug
build-debug:
	@echo "开发模式构建..."
	$(CARGO) build
	@echo "开发模式构建完成"

# 运行测试
# 执行所有单元测试和集成测试
.PHONY: test
test:
	@echo "运行测试套件..."
	$(CARGO) test
	@echo "测试完成"

# 运行测试并显示输出
# 用于调试失败的测试
.PHONY: test-verbose
test-verbose:
	@echo "运行详细测试..."
	$(CARGO) test -- --nocapture
	@echo "详细测试完成"

# 运行特定模块的测试
# 用法: make test-module MODULE=protocol
.PHONY: test-module
test-module:
ifndef MODULE
	@echo "错误: 请指定模块名称"
	@echo "用法: make test-module MODULE=<模块名>"
	@exit 1
endif
	@echo "测试模块: $(MODULE)"
	$(CARGO) test --lib $(MODULE)

# 运行基准测试
# 测量性能指标
.PHONY: bench
bench:
	@echo "运行基准测试..."
	$(CARGO) bench
	@echo "基准测试完成"

# 代码检查
# 运行clippy代码质量检查工具
.PHONY: check
check:
	@echo "运行代码检查..."
	$(CARGO) clippy
	@echo "代码检查完成"

# 代码格式化
# 使用rustfmt自动格式化代码
.PHONY: fmt
fmt:
	@echo "格式化代码..."
	$(CARGO) fmt
	@echo "代码格式化完成"

# 代码格式化检查
# 检查代码是否符合格式规范
.PHONY: fmt-check
fmt-check:
	@echo "检查代码格式..."
	$(CARGO) fmt -- --check
	@echo "代码格式检查完成"

# 依赖更新
# 更新Cargo.lock文件中的依赖版本
.PHONY: update
update:
	@echo "更新依赖..."
	$(CARGO) update
	@echo "依赖更新完成"

# 清理构建产物
# 删除所有生成的文件和目录
.PHONY: clean
clean:
	@echo "清理构建产物..."
	$(CARGO) clean
	@echo "清理完成"

# 深度清理
# 删除所有构建产物和依赖缓存
.PHONY: clean-all
clean-all: clean
	@echo "深度清理..."
	@rm -rf $(TARGET_DIR)
	@rm -f Cargo.lock
	@echo "深度清理完成"

# 安装项目
# 将库文件安装到系统目录（需要管理员权限）
.PHONY: install
install: build
	@echo "安装库文件..."
	@if [ -f "$(LIB_FILE)" ]; then \
		sudo cp "$(LIB_FILE)" /usr/local/lib/; \
		sudo ldconfig; \
		echo "库文件安装完成"; \
	else \
		echo "错误: 库文件不存在，请先构建项目"; \
		exit 1; \
	fi

# 安装头文件
# 将C头文件安装到系统目录
.PHONY: install-headers
install-headers: build
	@echo "安装头文件..."
	@if [ -f "$(HEADER_FILE)" ]; then \
		sudo cp "$(HEADER_FILE)" /usr/local/include/; \
		echo "头文件安装完成"; \
	else \
		echo "错误: 头文件不存在，请先构建项目"; \
		exit 1; \
	fi

# 完整安装
# 安装库文件和头文件
.PHONY: install-all
install-all: install install-headers
	@echo "完整安装完成"

# 卸载项目
# 从系统目录移除安装的文件
.PHONY: uninstall
uninstall:
	@echo "卸载库文件..."
	@sudo rm -f /usr/local/lib/$(LIB_NAME).$(LIB_EXT)
	@sudo rm -f /usr/local/include/$(PROJECT_NAME).h
	@sudo ldconfig
	@echo "卸载完成"

# 文档生成
# 生成API文档
.PHONY: doc
doc:
	@echo "生成API文档..."
	$(CARGO) doc --no-deps --open
	@echo "文档生成完成"

# 文档检查
# 检查文档是否完整
.PHONY: doc-check
doc-check:
	@echo "检查文档完整性..."
	$(CARGO) doc --no-deps
	@echo "文档检查完成"

# 发布构建
# 为生产环境构建优化的版本
.PHONY: release
release: clean build
	@echo "发布构建完成"
	@echo "发布文件位置: $(RELEASE_DIR)"

# 包管理
# 创建发布包
.PHONY: package
package: release
	@echo "创建发布包..."
	@mkdir -p dist
	@cp $(LIB_FILE) dist/
	@cp $(HEADER_FILE) dist/
	@cp README.md dist/
	@cp LICENSE dist/ 2>/dev/null || true
	@tar -czf dist/$(PROJECT_NAME)-$(VERSION).tar.gz -C dist .
	@echo "发布包已创建: dist/$(PROJECT_NAME)-$(VERSION).tar.gz"

# 代码覆盖率检查
# 需要安装cargo-tarpaulin工具
.PHONY: coverage
coverage:
	@echo "检查代码覆盖率..."
	@if command -v cargo-tarpaulin >/dev/null 2>&1; then \
		cargo tarpaulin --out Html; \
		echo "覆盖率报告已生成在target/tarpaulin/目录"; \
	else \
		echo "请先安装cargo-tarpaulin: cargo install cargo-tarpaulin"; \
		exit 1; \
	fi

# 安全检查
# 运行cargo audit检查依赖中的安全漏洞
.PHONY: audit
audit:
	@echo "检查依赖安全漏洞..."
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "请先安装cargo-audit: cargo install cargo-audit"; \
		exit 1; \
	fi

# 依赖树查看
# 显示项目的依赖关系树
.PHONY: tree
tree:
	@echo "显示依赖关系树..."
	$(CARGO) tree

# 大小分析
# 分析生成的二进制文件大小
.PHONY: size
size: build
	@echo "分析二进制文件大小..."
	@if command -v size >/dev/null 2>&1; then \
		size $(RELEASE_DIR)/$(LIB_NAME).*; \
	else \
		echo "size命令不可用"; \
	fi

# 帮助信息
.PHONY: help
help:
	@echo "Web扫描检测引擎 - 构建帮助"
	@echo ""
	@echo "可用目标:"
	@echo "  build          - 构建项目（发布模式）"
	@echo "  build-debug    - 构建项目（调试模式）"
	@echo "  test           - 运行测试"
	@echo "  test-verbose   - 运行详细测试"
	@echo "  test-module    - 测试特定模块（需要指定MODULE=<模块名>）"
	@echo "  bench          - 运行基准测试"
	@echo "  check          - 代码质量检查"
	@echo "  fmt            - 代码格式化"
	@echo "  fmt-check      - 检查代码格式"
	@echo "  update         - 更新依赖"
	@echo "  clean          - 清理构建产物"
	@echo "  clean-all      - 深度清理"
	@echo "  install        - 安装库文件"
	@echo "  install-headers- 安装头文件"
	@echo "  install-all    - 完整安装"
	@echo "  uninstall      - 卸载项目"
	@echo "  doc            - 生成API文档"
	@echo "  doc-check      - 检查文档完整性"
	@echo "  release        - 发布构建"
	@echo "  package        - 创建发布包"
	@echo "  coverage       - 代码覆盖率检查"
	@echo "  audit          - 安全检查"
	@echo "  tree           - 显示依赖关系树"
	@echo "  size           - 分析二进制文件大小"
	@echo "  help           - 显示此帮助信息"
	@echo ""
	@echo "示例用法:"
	@echo "  make build                    # 构建项目"
	@echo "  make test                     # 运行测试"
	@echo "  make test-module MODULE=protocol  # 测试协议模块"
	@echo "  make install-all              # 完整安装"
	@echo "  make clean                    # 清理构建产物"

# 默认目标
.DEFAULT_GOAL := help