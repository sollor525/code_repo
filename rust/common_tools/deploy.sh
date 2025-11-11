#!/bin/bash

# 开发者工具箱部署脚本
# 支持Ubuntu/CentOS/Debian系统

set -e

echo "🛠️ 开发者工具箱部署脚本"
echo "================================"

# 检测操作系统
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$NAME
            VER=$VERSION_ID
        fi
    else
        echo "❌ 不支持的操作系统: $OSTYPE"
        exit 1
    fi
    echo "📋 检测到操作系统: $OS $VER"
}

# 安装Rust
install_rust() {
    if ! command -v cargo &> /dev/null; then
        echo "🦀 安装Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source ~/.cargo/env
    else
        echo "✅ Rust已安装"
    fi
}

# 安装系统依赖
install_dependencies() {
    echo "📦 安装系统依赖..."

    case "$OS" in
        "Ubuntu"*|"Debian"*)
            sudo apt update
            sudo apt install -y build-essential pkg-config libssl-dev
            ;;
        "CentOS"*|"Red Hat"*)
            sudo yum groupinstall -y "Development Tools"
            sudo yum install -y openssl-devel pkg-config
            ;;
        *)
            echo "⚠️  请手动安装: build-essential, pkg-config, libssl-dev"
            ;;
    esac
}

# 创建部署目录
create_directory() {
    echo "📁 创建部署目录..."
    DEPLOY_DIR="/opt/common_tools"
    sudo mkdir -p $DEPLOY_DIR
    sudo chown $USER:$USER $DEPLOY_DIR
    cd $DEPLOY_DIR
}

# 克隆或更新代码
deploy_code() {
    if [ -d ".git" ]; then
        echo "🔄 更新代码..."
        git pull origin master
    else
        echo "📥 克隆代码..."
        # 这里需要替换为实际的仓库地址
        echo "请手动上传代码包或从git仓库克隆"
        # git clone <repository-url> .
    fi
}

# 构建项目
build_project() {
    echo "🔨 构建项目..."
    cargo build --release
}

# 创建systemd服务
create_service() {
    echo "⚙️  创建系统服务..."
    sudo tee /etc/systemd/system/common-tools.service > /dev/null <<EOF
[Unit]
Description=开发者工具箱 Web服务
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$DEPLOY_DIR
ExecStart=$DEPLOY_DIR/target/release/common_tools
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable common-tools
}

# 启动服务
start_service() {
    echo "🚀 启动服务..."
    sudo systemctl start common-tools
    sudo systemctl status common-tools --no-pager
}

# 防火墙配置
configure_firewall() {
    echo "🔥 配置防火墙..."
    if command -v ufw &> /dev/null; then
        sudo ufw allow 8080/tcp
    elif command -v firewall-cmd &> /dev/null; then
        sudo firewall-cmd --add-port=8080/tcp --permanent
        sudo firewall-cmd --reload
    else
        echo "⚠️  请手动开放8080端口"
    fi
}

# 主函数
main() {
    detect_os
    install_rust
    install_dependencies
    create_directory
    deploy_code
    build_project
    create_service
    configure_firewall
    start_service

    echo ""
    echo "🎉 部署完成！"
    echo "📡 服务地址: http://$(hostname -I | awk '{print $1}'):8080"
    echo "🔧 管理命令:"
    echo "   启动: sudo systemctl start common-tools"
    echo "   停止: sudo systemctl stop common-tools"
    echo "   重启: sudo systemctl restart common-tools"
    echo "   状态: sudo systemctl status common-tools"
    echo "   日志: sudo journalctl -u common-tools -f"
}

# 执行主函数
main