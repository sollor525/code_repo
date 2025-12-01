#!/bin/bash
# scripts/setup_env.sh

set -e

echo "=== 设置DPDK运行环境 ==="

# 检查root权限
if [ "$EUID" -ne 0 ]; then 
    echo "请使用sudo运行此脚本"
    exit 1
fi

# 配置hugepages
configure_hugepages() {
    echo "配置hugepages..."
    
    # 清理现有
    umount /mnt/huge 2>/dev/null || true
    rm -rf /dev/hugepages/*
    
    # 设置2MB hugepages
    echo 1024 > /proc/sys/vm/nr_hugepages
    
    # 挂载
    mkdir -p /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
    
    # 验证
    echo "Hugepages状态:"
    grep HugePages_Total /proc/meminfo
    grep HugePages_Free /proc/meminfo
}

# 设置CPU隔离
setup_cpu_affinity() {
    echo "设置CPU亲和性..."
    
    # 隔离CPU 1-3供DPDK使用
    for cpu in 1 2 3; do
        echo 0 > /sys/devices/system/cpu/cpu${cpu}/online 2>/dev/null || true
        echo 1 > /sys/devices/system/cpu/cpu${cpu}/online 2>/dev/null || true
    done
}

# 设置环境变量
setup_env_vars() {
    echo "设置环境变量..."
    
    cat > /etc/profile.d/dpdk_demo.sh << 'EOF'
export DPDK_DEMO_ROOT=/root/workspace/code_repo/dpdk/rte_ring_demo
export PATH=$DPDK_DEMO_ROOT/build/bin:$PATH
EOF
    
    source /etc/profile.d/dpdk_demo.sh
}

# 验证设置
verify_setup() {
    echo "验证环境设置..."
    
    # 检查hugepages
    if ! grep -q "HugePages_Total" /proc/meminfo; then
        echo "错误: Hugepages未正确配置"
        return 1
    fi
    
    echo "✅ 环境设置完成"
}

main() {
    configure_hugepages
    setup_cpu_affinity
    setup_env_vars
    verify_setup
    
    echo ""
    echo "=== 设置完成 ==="
    echo "现在可以构建和运行DPDK Ring Demo:"
    echo "  1. 构建: mkdir build && cd build && cmake .. && make"
    echo "  2. 运行: sudo ./bin/dpdk_ring_demo -l 0-2 --socket-mem=256,0 --no-pci"
}

main "$@"