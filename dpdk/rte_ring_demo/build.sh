#!/bin/bash
# build.sh - 修复版本

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
DPDK_PATH="/root/workspace/qt/npatch_all_in_one/fp-vpp/vpp/build-root/install-vpp_debug-native"

echo "项目目录: ${PROJECT_ROOT}"
echo "DPDK路径: ${DPDK_PATH}"

# 检查必要库
REQUIRED_LIBS=(
    "librte_eal.a"
    "librte_ring.a"
    "librte_mempool.a"
    "librte_mbuf.a"
)

echo "检查必要库..."
for lib in "${REQUIRED_LIBS[@]}"; do
    if [ -f "${DPDK_PATH}/external/lib/${lib}" ]; then
        echo "✅ ${lib}"
    else
        echo "❌ ${lib} 缺失"
        exit 1
    fi
done

# 创建构建目录
BUILD_DIR="${PROJECT_ROOT}/build"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# 运行CMake
echo "配置CMake..."
cmake "${PROJECT_ROOT}" \
    -DDPDK_VPP_PATH="${DPDK_PATH}" \
    -DCMAKE_BUILD_TYPE=Debug

echo "编译..."
make -j$(nproc)

echo ""
echo "✅ 构建成功!"
echo "可执行文件: ${BUILD_DIR}/ring_demo"rm -rf build