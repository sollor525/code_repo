#!/bin/bash

# TLS JA4 Examples Build Script
# 这个脚本用于构建C示例程序

set -e

echo "🚀 Building TLS JA4 Examples"
echo "============================="

# 检查是否在正确的目录
if [ ! -f "vpp_integration_example.c" ]; then
    echo "❌ Error: Please run this script from the examples directory"
    exit 1
fi

# 检查Rust是否安装
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Cargo not found. Please install Rust first"
    exit 1
fi

# 检查CMake是否安装
if ! command -v cmake &> /dev/null; then
    echo "❌ Error: CMake not found. Please install CMake first"
    exit 1
fi

echo "📦 Building Rust library..."
cd ..
cargo build
cd examples

echo "🔧 Configuring CMake..."
mkdir -p build
cd build

# 配置CMake
cmake .. -DCMAKE_BUILD_TYPE=Debug

echo "🔨 Building C example..."
make

echo "✅ Build completed successfully!"
echo ""
echo "📋 Usage:"
echo "  ./vpp_integration_example"
echo ""
echo "📁 Files created:"
echo "  - vpp_integration_example (executable)"
echo "  - build/ (build directory)"
echo ""
echo "🧹 To clean:"
echo "  rm -rf build/"
