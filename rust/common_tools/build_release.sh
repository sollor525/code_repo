#!/bin/bash

# 构建二进制发布包 - 简化版本

set -e

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "🏗️ 构建二进制发布包"
echo "==================="

# 项目信息
PROJECT_NAME="common_tools"
VERSION=$(cargo metadata --no-deps --format-version 1 2>/dev/null | grep -o '"version":"[^"]*"' | cut -d'"' -f4 | head -1 || echo "1.0.0")
RELEASE_DIR="$SCRIPT_DIR/release"

# 创建发布目录
echo "📁 创建发布目录: $RELEASE_DIR"
mkdir -p "$RELEASE_DIR"

# 检查必要文件
echo "🔍 检查必要文件..."
if [ ! -f "Cargo.toml" ]; then
    echo "❌ 错误: 找不到 Cargo.toml 文件"
    exit 1
fi

if [ ! -d "src" ]; then
    echo "❌ 错误: 找不到 src 目录"
    exit 1
fi

if [ ! -d "static" ]; then
    echo "❌ 错误: 找不到 static 目录"
    exit 1
fi

# 构建Linux版本
echo "🔨 构建Linux x64版本..."
if cargo build --release; then
    BINARY_PATH="target/release/$PROJECT_NAME"
    if [ -f "$BINARY_PATH" ]; then
        # 创建二进制包
        PACKAGE_NAME="${PROJECT_NAME}-${VERSION}-linux-x64.tar.gz"
        cd target/release
        tar -czf "$RELEASE_DIR/$PACKAGE_NAME" "$PROJECT_NAME"
        cd "$SCRIPT_DIR"
        echo "✅ 生成二进制包: $RELEASE_DIR/$PACKAGE_NAME"

        # 创建完整部署包
        echo "📦 创建完整部署包..."
        TEMP_DIR="${PROJECT_NAME}-${VERSION}-deploy"
        TEMP_PATH="$RELEASE_DIR/$TEMP_DIR"
        mkdir -p "$TEMP_PATH"

        # 解压二进制文件
        echo "📂 解压二进制文件..."
        tar -xzf "$RELEASE_DIR/$PACKAGE_NAME" -C "$TEMP_PATH"

        # 复制静态文件
        echo "📋 复制静态文件..."
        cp -r "static" "$TEMP_PATH/"

        # 复制配置文件
        echo "📄 复制配置文件..."
        [ -f "DEPLOYMENT.md" ] && cp "DEPLOYMENT.md" "$TEMP_PATH/"
        [ -f "deploy.sh" ] && cp "deploy.sh" "$TEMP_PATH/"
        [ -f "docker-deploy.sh" ] && cp "docker-deploy.sh" "$TEMP_PATH/"
        [ -f "README.md" ] && cp "README.md" "$TEMP_PATH/" || echo "# 开发者工具箱" > "$TEMP_PATH/README.md"

        # 创建启动脚本
        echo "🚀 创建启动脚本..."
        cat > "$TEMP_PATH/start.sh" << 'EOF'
#!/bin/bash
# 开发者工具箱启动脚本

APP_DIR="$(dirname "$0")"
BINARY="$APP_DIR/common_tools"
STATIC_DIR="$APP_DIR/static"

# 检查二进制文件
if [ ! -f "$BINARY" ]; then
    echo "❌ 二进制文件不存在: $BINARY"
    exit 1
fi

# 检查静态文件目录
if [ ! -d "$STATIC_DIR" ]; then
    echo "❌ 静态文件目录不存在: $STATIC_DIR"
    exit 1
fi

# 设置工作目录
cd "$APP_DIR"

# 启动服务
echo "🚀 启动开发者工具箱..."
echo "📡 访问地址: http://localhost:8080"
echo "🛑 按 Ctrl+C 停止服务"
echo ""

exec "$BINARY"
EOF

        chmod +x "$TEMP_PATH/start.sh"

        # 创建systemd服务文件
        echo "⚙️ 创建系统服务文件..."
        cat > "$TEMP_PATH/common-tools.service" << EOF
[Unit]
Description=开发者工具箱 Web服务
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/common_tools
ExecStart=/opt/common_tools/common_tools
Restart=always
RestartSec=10
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

        # 打包完整部署包
        echo "📦 打包部署包..."
        cd "$RELEASE_DIR"
        tar -czf "${PROJECT_NAME}-${VERSION}-deploy.tar.gz" "$TEMP_DIR"
        rm -rf "$TEMP_DIR"
        cd "$SCRIPT_DIR"

        echo "✅ 完整部署包: $RELEASE_DIR/${PROJECT_NAME}-${VERSION}-deploy.tar.gz"
    else
        echo "❌ 错误: 二进制文件构建失败"
        exit 1
    fi
else
    echo "❌ 错误: 构建失败"
    exit 1
fi

echo ""
echo "🎉 构建完成！"
echo "📁 发布文件位置: $RELEASE_DIR"
echo "📋 生成的文件:"
ls -la "$RELEASE_DIR/"
echo ""
echo "🚀 快速部署:"
echo "1. 上传 ${PROJECT_NAME}-${VERSION}-deploy.tar.gz 到目标服务器"
echo "2. 解压: tar -xzf ${PROJECT_NAME}-${VERSION}-deploy.tar.gz"
echo "3. 运行: cd ${PROJECT_NAME}-${VERSION}-deploy && ./start.sh"