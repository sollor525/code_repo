#!/bin/bash

# TLS JA4/JA3 构建脚本
# 支持生成C兼容的静态库供VPP使用

set -e

echo "Building TLS JA4/JA3 library..."

# 创建必要的目录
mkdir -p include
mkdir -p lib

# 构建Rust库
echo "Building Rust library..."
cargo build --release

# 复制头文件
echo "Copying header files..."
cp include/tls_ja4.h include/

# 生成静态库（如果需要的话）
# 注意：实际使用时，可能只需要动态库或直接链接Rust代码
echo "Build completed!"
echo ""
echo "Usage in VPP:"
echo "1. Copy include/tls_ja4.h to your VPP include path"
echo "2. Link against the Rust library or compile as part of VPP"
echo "3. Use the C API functions in your VPP nodes"
echo ""
echo "Example:"
echo "  #include \"tls_ja4.h\""
echo "  TlsJa4Result result;"
echo "  tls_ja4_analyze_payload(ctx, payload, len, &result);"
