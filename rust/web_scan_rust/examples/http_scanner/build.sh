#!/bin/bash

# HTTP扫描器构建脚本
# 自动构建Rust库和C程序

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

if ! pkg-config --exists hyperscan; then
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

# 检查生成的文件
if [ ! -f "target/release/libweb_scan_rust.so" ]; then
    echo -e "${RED}❌ 错误: 未找到生成的libweb_scan_rust.so${NC}"
    exit 1
fi

if [ ! -f "target/include/web_scan_rust.h" ]; then
    echo -e "${RED}❌ 错误: 未找到生成的头文件web_scan_rust.h${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Rust库构建成功${NC}"

# 4. 创建build目录
echo -e "${BLUE}📁 准备CMake构建目录...${NC}"
cd "$SCRIPT_DIR"
mkdir -p build
cd build

# 5. CMake构建C程序
echo -e "${BLUE}🔨 使用CMake构建C程序...${NC}"
cmake .. -DCMAKE_BUILD_TYPE=Release

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ CMake配置失败${NC}"
    exit 1
fi

make -j$(nproc)

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ C程序编译失败${NC}"
    exit 1
fi

echo -e "${GREEN}✅ C程序构建成功${NC}"

# 6. 检查生成的可执行文件
if [ ! -f "http_scanner" ]; then
    echo -e "${RED}❌ 错误: 未找到生成的http_scanner可执行文件${NC}"
    exit 1
fi

echo -e "${GREEN}✅ http_scanner可执行文件生成成功${NC}"

# 7. 测试程序
echo -e "${BLUE}🧪 测试程序功能...${NC}"

# 设置库路径
export LD_LIBRARY_PATH="$PROJECT_ROOT/target/release:$LD_LIBRARY_PATH"

echo -e "${BLUE}测试程序帮助信息...${NC}"
./http_scanner --help

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ 程序帮助测试通过${NC}"
else
    echo -e "${RED}❌ 程序帮助测试失败${NC}"
    exit 1
fi

echo -e "${BLUE}测试程序版本信息...${NC}"
./http_scanner --version

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ 程序版本测试通过${NC}"
else
    echo -e "${RED}❌ 程序版本测试失败${NC}"
    exit 1
fi

# 8. 检查规则文件
echo -e "${BLUE}📋 检查规则文件...${NC}"
RULES_DIR="$SCRIPT_DIR/rules"
if [ ! -d "$RULES_DIR" ]; then
    echo -e "${YELLOW}⚠️  规则目录不存在，创建...${NC}"
    mkdir -p "$RULES_DIR"
fi

RULE_COUNT=$(find "$RULES_DIR" -name "*.rules" | wc -l)
if [ "$RULE_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  规则目录为空${NC}"
else
    echo -e "${GREEN}✅ 找到 $RULE_COUNT 个规则文件${NC}"
    find "$RULES_DIR" -name "*.rules" -exec basename {} \;
fi

# 9. 生成启动脚本
echo -e "${BLUE}📝 生成启动脚本...${NC}"
RUN_SCRIPT="$SCRIPT_DIR/build/run_scanner.sh"
if [ -f "$RUN_SCRIPT" ]; then
    echo -e "${GREEN}✅ 启动脚本已生成${NC}"
else
    echo -e "${YELLOW}⚠️  启动脚本未找到${NC}"
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}🎉 HTTP扫描器构建完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo "构建产物:"
echo "  可执行文件: $SCRIPT_DIR/build/http_scanner"
echo "  启动脚本: $RUN_SCRIPT"
echo "  Rust库: $PROJECT_ROOT/target/release/libweb_scan_rust.so"
echo "  头文件: $PROJECT_ROOT/target/include/web_scan_rust.h"
echo ""
echo "使用方法:"
echo "  1. 直接运行: cd build && ./http_scanner --help"
echo "  2. 使用启动脚本: $RUN_SCRIPT --rules ../rules --pcap sample.pcap"
echo "  3. 查看版本: $RUN_SCRIPT --version"
echo ""
echo -e "${BLUE}💡 提示: 确保Hyperscan库路径正确设置${NC}"