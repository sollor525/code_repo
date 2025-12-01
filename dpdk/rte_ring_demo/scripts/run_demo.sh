#!/bin/bash
# scripts/run_demo.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"

# 默认参数
CPU_MASK="0x7"      # CPU 0-2
MEMORY="256,0"      # 256MB在socket 0
LOG_LEVEL="info"
RUN_TIME=30

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--cpu-mask)
            CPU_MASK="$2"
            shift 2
            ;;
        -m|--memory)
            MEMORY="$2"
            shift 2
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        -t|--time)
            RUN_TIME="$2"
            shift 2
            ;;
        -h|--help)
            echo "用法: $0 [选项]"
            echo "选项:"
            echo "  -c, --cpu-mask    CPU掩码 (默认: 0x7)"
            echo "  -m, --memory      内存配置 (默认: 256,0)"
            echo "  -l, --log-level   日志级别 (默认: info)"
            echo "  -t, --time        运行时间(秒) (默认: 30)"
            echo "  -h, --help        显示帮助"
            exit 0
            ;;
        *)
            echo "未知选项: $1"
            exit 1
            ;;
    esac
done

# 检查可执行文件
EXECUTABLE="${BUILD_DIR}/bin/dpdk_ring_demo"
if [ ! -f "${EXECUTABLE}" ]; then
    echo "错误: 找不到可执行文件 ${EXECUTABLE}"
    echo "请先构建项目: mkdir build && cd build && cmake .. && make"
    exit 1
fi

# 运行DPDK应用
echo "运行DPDK Ring Demo..."
echo "参数:"
echo "  CPU掩码:    ${CPU_MASK}"
echo "  内存配置:   ${MEMORY}"
echo "  日志级别:   ${LOG_LEVEL}"
echo "  运行时间:   ${RUN_TIME}秒"
echo ""

sudo ${EXECUTABLE} \
    -l ${CPU_MASK} \
    --socket-mem ${MEMORY} \
    --log-level ${LOG_LEVEL} \
    --no-pci \
    --no-hpet \
    --file-prefix ring_demo_run

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo "✅ DPDK应用运行成功"
else
    echo "❌ DPDK应用运行失败 (退出码: $exit_code)"
fi

exit $exit_code