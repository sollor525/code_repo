#!/bin/bash
#
# HTTP扫描器构建脚本
# 自动设置库路径并构建扫描器

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo -e "${BLUE}🚀 开始构建HTTP扫描器${NC}"
echo "项目根目录: $PROJECT_ROOT"
echo "构建目录: $SCRIPT_DIR"
echo "========================================"

# 1. 检查Rust环境
echo -e "${BLUE}📋 检查Rust环境...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ 错误: 未找到Rust cargo工具${NC}"
    echo "请安装Rust: https://rustup.rs/"
    exit 1
fi
echo -e "${GREEN}✅ Rust环境检查通过${NC}"

# 2. 检查Hyperscan环境
echo -e "${BLUE}📋 检查Hyperscan环境...${NC}"
export PKG_CONFIG_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan:$LD_LIBRARY_PATH"

if ! pkg-config --exists hyperscan && ! pkg-config --exists libhs; then
    echo -e "${RED}❌ 错误: 未找到Hyperscan库${NC}"
    echo "请确保Hyperscan已安装且pkg-config路径正确"
    exit 1
fi
echo -e "${GREEN}✅ Hyperscan环境检查通过${NC}"

# 3. 构建Rust库
echo -e "${BLUE}🔨 构建Web扫描检测Rust库...${NC}"
cd "$PROJECT_ROOT"
cargo build --release --features hyperscan
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Rust库构建失败${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Rust库构建成功${NC}"

# 4. 构建HTTP扫描器
echo -e "${BLUE}🚀 构建HTTP扫描器可执行文件...${NC}"
cd "$SCRIPT_DIR"
cmake .
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ CMake配置失败${NC}"
    exit 1
fi

make
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ 扫描器构建失败${NC}"
    exit 1
fi

echo -e "${GREEN}✅ HTTP扫描器构建成功${NC}"
echo "========================================"
echo -e "${GREEN}🎉 所有组件构建完成！${NC}"
echo -e "${BLUE}📁 生成的可执行文件: $SCRIPT_DIR/http_scanner${NC}"
echo -e "${BLUE}📁 使用方法: $SCRIPT_DIR/http_scanner -r /path/to/rules.rules -p 8080 -i eth0${NC}"
echo -e "${BLUE}📁 更多选项: $SCRIPT_DIR/http_scanner --help${NC}"