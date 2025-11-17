#!/bin/bash

# Web扫描检测库编译和测试脚本
# 
# 这个脚本用于编译Rust库并测试C集成

set -e  # 遇到错误时退出

echo "=== Web扫描检测库编译和测试脚本 ==="
echo

# 检查是否安装了必要的工具
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "错误: $1 未安装"
        echo "请安装 $1 后重试"
        exit 1
    fi
}

echo "1. 检查必要的工具..."
check_tool "cargo"
check_tool "cmake"
check_tool "make"

echo "2. 清理之前的构建..."
rm -rf target/
rm -rf build/

echo "3. 设置Hyperscan环境..."
export PKG_CONFIG_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan"
export LD_LIBRARY_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan:$LD_LIBRARY_PATH"

echo "4. 检查Hyperscan库..."
# 检查pkg-config文件是否存在
if [ ! -f "/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan/libhs.pc" ]; then
    echo "警告: Hyperscan pkg-config文件不存在，尝试生成..."
    
    # 尝试生成pkg-config文件
    cd /root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan/
    
    # 设置环境变量
    export CMAKE_INSTALL_PREFIX="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan"
    export CMAKE_INSTALL_LIBDIR="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan/lib"
    export CMAKE_INSTALL_INCLUDEDIR="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan/include"
    
    # 从模板生成pkg-config文件
    if [ -f "libhs.pc.in" ]; then
        sed -e "s/@CMAKE_INSTALL_PREFIX@/\${CMAKE_INSTALL_PREFIX}/g" \
           -e "s/@CMAKE_INSTALL_LIBDIR@/\${CMAKE_INSTALL_LIBDIR}/g" \
           -e "s/@CMAKE_INSTALL_INCLUDEDIR@/\${CMAKE_INSTALL_INCLUDEDIR}/g" \
           -e "s/@HS_VERSION@/5.4.0/g" \
           "libhs.pc.in" > "libhs.pc"
        
        echo "✓ 生成了libhs.pc文件"
    else
        echo "错误: 找不到libhs.pc.in模板文件"
        exit 1
    fi
    
    cd /root/workspace/code_repo/rust/web_scan_rust
else
    echo "✓ 找到Hyperscan pkg-config文件"
fi

echo "5. 构建Rust库..."
# 构建发布版本，确保 Hyperscan 环境变量正确设置
PKG_CONFIG_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan" cargo build --release

if [ $? -ne 0 ]; then
    echo "错误: Rust库构建失败"
    exit 1
fi

echo "6. 验证构建产物..."
if [ ! -f "target/release/libweb_scan_rust.so" ]; then
    echo "错误: 动态库未找到"
    exit 1
fi

if [ ! -f "target/include/web_scan_rust.h" ]; then
    echo "错误: C头文件未找到"
    exit 1
fi

echo "✓ Rust库构建成功"
echo "  - 动态库: target/release/libweb_scan_rust.so"
echo "  - 静态库: target/release/libweb_scan_rust.rlib"
echo "  - C头文件: target/include/web_scan_rust.h"

echo "7. 创建构建目录..."
mkdir -p build

echo "8. 创建CMakeLists.txt..."
cat > CMakeLists.txt << 'EOF'
cmake_minimum_required(VERSION 3.10)
project(web_scan_rust_integration)

# 设置 C 标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 查找必要的库
find_package(PkgConfig REQUIRED)

# 查找 Hyperscan
pkg_check_modules(HYPERSCAN REQUIRED libhs)

# 添加 Hyperscan 的包含路径和库
include_directories(${HYPERSCAN_INCLUDE_DIRS})
link_directories(${HYPERSCAN_LIBRARY_DIRS})

# 设置 Rust 库的路径
set(RUST_LIB_PATH "${CMAKE_CURRENT_SOURCE_DIR}/target/release")
set(RUST_INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/target/include")

# 包含 Rust 头文件
include_directories(${RUST_INCLUDE_PATH})

# 添加链接目录
link_directories(${RUST_LIB_PATH})

# 创建 C 集成测试可执行文件
add_executable(c_integration_test examples/c_integration.c)

# 链接必要的库
target_link_libraries(c_integration_test
    web_scan_rust
    ${HYPERSCAN_LIBRARIES}
    pthread
    dl
    m
)

# 设置编译选项
target_compile_options(c_integration_test PRIVATE ${HYPERSCAN_CFLAGS_OTHER})

# 添加 RPATH 以便找到动态库
set_target_properties(c_integration_test PROPERTIES
    INSTALL_RPATH "${RUST_LIB_PATH}"
    BUILD_WITH_INSTALL_RPATH TRUE
)
EOF

cd build

echo "9. 配置CMake..."
PKG_CONFIG_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan" cmake .. -DCMAKE_BUILD_TYPE=Release

if [ $? -ne 0 ]; then
    echo "错误: CMake配置失败"
    exit 1
fi

echo "10. 编译C集成测试..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo "错误: C集成测试编译失败"
    exit 1
fi

echo "11. 运行C集成测试..."
echo "----------------------------------------"
LD_LIBRARY_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan/build/lib:$LD_LIBRARY_PATH" ./c_integration_test
echo "----------------------------------------"

if [ $? -eq 0 ]; then
    echo
    echo "✓ C集成测试成功完成"
else
    echo "错误: C集成测试失败"
    exit 1
fi

echo "12. 运行Rust单元测试..."
cd ..
cargo test

if [ $? -eq 0 ]; then
    echo
    echo "✓ 所有测试通过"
else
    echo "错误: 部分测试失败"
    exit 1
fi

echo "=== 构建和测试完成 ==="
echo
echo "生成的文件："
echo "  - Rust动态库: target/release/libweb_scan_rust.so"
echo "  - Rust静态库: target/release/libweb_scan_rust.rlib"
echo "  - C头文件: target/include/web_scan_rust.h"
echo "  - C测试程序: build/c_integration_test"
echo "使用方法："
echo "  1. 将libweb_scan_rust.so和web_scan_rust.h集成到你的C项目中"
echo "  2. 参考examples/c_integration.c了解如何使用API"
echo "  3. 运行./build/c_integration_test测试集成"