# DPDK Ring Demo

一个展示DPDK rte_ring使用的完整示例工程。

## 功能特性

- 多生产者/消费者ring缓冲区
- 完整的CMake构建系统
- 自动DPDK库查找
- 环境配置脚本
- 详细的日志输出

## 构建要求

- CMake 3.12+
- GCC 7+
- DPDK 20.11+ (通过VPP集成)
- libnuma-dev

## 构建步骤

```bash
# 1. 克隆代码
cd /root/workspace/code_repo/dpdk
git clone <repository> rte_ring_demo
cd rte_ring_demo

# 2. 设置环境(需要root)
sudo bash scripts/setup_env.sh

# 3. 构建
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)