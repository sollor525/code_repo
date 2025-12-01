#!/bin/bash
# check_vpp_libs.sh

DPDK_PATH="/root/workspace/qt/npatch_all_in_one/fp-vpp/vpp/build-root/install-vpp_debug-native"
LIB_DIR="${DPDK_PATH}/external/lib"

echo "检查VPP中的DPDK库..."
echo "库目录: ${LIB_DIR}"
echo ""

# 列出所有.a文件
echo "所有静态库文件:"
ls -1 ${LIB_DIR}/*.a 2>/dev/null | xargs -n1 basename

echo ""
echo "核心库检查:"
for lib in librte_eal.a librte_ring.a librte_mempool.a librte_mbuf.a; do
    if [ -f "${LIB_DIR}/${lib}" ]; then
        echo "✅ ${lib}"
    else
        echo "❌ ${lib} (缺失)"
    fi
done

echo ""
echo "库依赖检查:"
for lib in ${LIB_DIR}/*.a; do
    echo "检查 $(basename $lib):"
    nm --defined-only "$lib" 2>/dev/null | grep -q "rte_ring_create" && echo "  包含 rte_ring_create"
    nm --defined-only "$lib" 2>/dev/null | grep -q "rte_eal_init" && echo "  包含 rte_eal_init"
done