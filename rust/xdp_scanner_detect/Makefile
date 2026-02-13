# xdp-scanner-detect Makefile

.PHONY: all build clean install uninstall test fmt check docker docker-build docker-run help

# 变量定义
CARGO = cargo
TARGET_DIR = target/release
BPF_TARGET_DIR = target/bpfel-unknown-none/release
PROGRAM_NAME = xdp-scanner-detect
SERVICE_NAME = xdp-scanner-detect

# 默认目标
all: build

# 构建所有组件
build:
	@echo "构建 xdp-scanner-detect..."
	$(CARGO) build --release

# 只构建用户空间程序
build-user:
	@echo "构建用户空间程序..."
	$(CARGO) build --release --bin $(PROGRAM_NAME)

# 只构建 eBPF 程序
build-bpf:
	@echo "构建 eBPF 程序..."
	$(CARGO) build --release --manifest-path ebpf/Cargo.toml

# 清理构建文件
clean:
	@echo "清理构建文件..."
	$(CARGO) clean

# 安装到系统
install: build
	@echo "安装 xdp-scanner-detect..."
	sudo mkdir -p /opt/xdp-scanner-detect
	sudo cp $(TARGET_DIR)/$(PROGRAM_NAME) /opt/xdp-scanner-detect/
	sudo cp config.toml /opt/xdp-scanner-detect/
	sudo chown -R root:root /opt/xdp-scanner-detect
	sudo chmod +x /opt/xdp-scanner-detect/$(PROGRAM_NAME)
	@echo "安装完成：/opt/xdp-scanner-detect/$(PROGRAM_NAME)"

# 卸载
uninstall:
	@echo "卸载 xdp-scanner-detect..."
	sudo rm -rf /opt/xdp-scanner-detect
	sudo rm -f /etc/systemd/system/$(SERVICE_NAME).service
	@echo "卸载完成"

# 运行测试
test:
	@echo "运行测试..."
	$(CARGO) test

# 代码格式化
fmt:
	@echo "格式化代码..."
	$(CARGO) fmt

# 代码检查
check:
	@echo "检查代码..."
	$(CARGO) check
	$(CARGO) clippy -- -D warnings

# 安全检查
audit:
	@echo "安全审计..."
	$(CARGO) audit

# 开发模式运行
run-dev:
	@echo "开发模式运行..."
	sudo $(TARGET_DIR)/$(PROGRAM_NAME) --log-level debug

# 生产模式运行
run-prod:
	@echo "生产模式运行..."
	sudo $(TARGET_DIR)/$(PROGRAM_NAME)

# 安装 systemd 服务
install-service:
	@echo "安装 systemd 服务..."
	sudo cp scripts/$(SERVICE_NAME).service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable $(SERVICE_NAME)
	@echo "服务安装完成"

# 启动服务
start-service:
	@echo "启动 xdp-scanner-detect 服务..."
	sudo systemctl start $(SERVICE_NAME)

# 停止服务
stop-service:
	@echo "停止 xdp-scanner-detect 服务..."
	sudo systemctl stop $(SERVICE_NAME)

# 查看服务状态
status-service:
	@echo "查看服务状态..."
	sudo systemctl status $(SERVICE_NAME)

# 查看服务日志
logs-service:
	@echo "查看服务日志..."
	sudo journalctl -u $(SERVICE_NAME) -f

# 性能测试
bench:
	@echo "运行性能测试..."
	$(CARGO) bench

# 文档生成
docs:
	@echo "生成文档..."
	$(CARGO) doc --no-deps --open

# Docker 构建
docker-build:
	@echo "构建 Docker 镜像..."
	docker build -t $(PROGRAM_NAME):latest .

# Docker 运行
docker-run:
	@echo "运行 Docker 容器..."
	docker run --privileged --network=host -v /config.toml:/config.toml $(PROGRAM_NAME):latest

# 创建发布包
package:
	@echo "创建发布包..."
	mkdir -p dist
	cp $(TARGET_DIR)/$(PROGRAM_NAME) dist/
	cp config.toml dist/
	cp README.md dist/
	cp LICENSE dist/
	tar czf $(PROGRAM_NAME)-$(shell git describe --tags).tar.gz -C dist .

# 检查系统要求
check-system:
	@echo "检查系统要求..."
	@./scripts/check-system.sh

# 设置开发环境
setup-dev:
	@echo "设置开发环境..."
	@./scripts/setup-dev.sh

# 帮助信息
help:
	@echo "xdp-scanner-detect 构建系统"
	@echo ""
	@echo "可用目标："
	@echo "  all            - 构建所有组件"
	@echo "  build          - 构建所有组件（同 all）"
	@echo "  build-user     - 只构建用户空间程序"
	@echo "  build-bpf      - 只构建 eBPF 程序"
	@echo "  clean          - 清理构建文件"
	@echo "  install        - 安装到系统"
	@echo "  uninstall      - 从系统卸载"
	@echo "  test           - 运行测试"
	@echo "  fmt            - 代码格式化"
	@echo "  check          - 代码检查"
	@echo "  audit          - 安全审计"
	@echo "  run-dev        - 开发模式运行"
	@echo "  run-prod       - 生产模式运行"
	@echo "  install-service - 安装 systemd 服务"
	@echo "  start-service  - 启动服务"
	@echo "  stop-service   - 停止服务"
	@echo "  status-service - 查看服务状态"
	@echo "  logs-service   - 查看服务日志"
	@echo "  bench          - 性能测试"
	@echo "  docs           - 生成文档"
	@echo "  docker-build   - Docker 构建"
	@echo "  docker-run     - Docker 运行"
	@echo "  package        - 创建发布包"
	@echo "  check-system   - 检查系统要求"
	@echo "  setup-dev      - 设置开发环境"
	@echo "  help           - 显示此帮助信息"