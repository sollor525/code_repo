# DPDK FDIR Demo

这是一个DPDK FDIR（Flow Director）的演示程序，展示了如何使用rte_flow API实现数据包的分类和重定向功能。

## 功能特性

- 支持基于IP地址、端口号、VLAN标签的数据包过滤
- 支持IPv4和IPv6协议
- 支持TCP和UDP协议
- 支持HTTP和TLS应用层协议识别
- 支持多队列分发
- 提供实时统计功能
- 支持配置文件加载

## 编译要求

- DPDK 21.11或更高版本
- CMake 3.12或更高版本
- GCC 7.5或更高版本
- 支持DPDK的网卡

## 编译步骤

1. 创建编译目录
```bash
mkdir build && cd build
```

2. 配置CMake
```bash
cmake -DCMAKE_BUILD_TYPE=Release ..
```

3. 编译
```bash
make -j
```

## 运行方式

### 基本运行
```bash
sudo ./dpdk_fdir_demo -c 0xf -n 4 -- -p 0x1 -q 8 -s
```

参数说明：
- `-c 0xf`: 使用CPU核心0-3
- `-n 4`: 使用4个内存通道
- `-p 0x1`: 使用端口0
- `-q 8`: 每端口8个队列
- `-s`: 启用统计功能

### 使用配置文件
```bash
sudo ./dpdk_fdir_demo -c 0xf -n 4 -- -p 0x1 -q 8 -s -c config/fdir_rules.conf
```

### 完整参数说明
```
Application options:
  -p PORT-MASK        Hexadecimal bitmask of ports to use
  -q NB-QUEUES        Number of Rx/Tx queues per port
  -s                  Enable statistics
  -i INTERVAL         Statistics interval in seconds (default: 1)
  -c FILE             Configuration file for flow rules
  --no-http           Disable HTTP pattern matcher
  --no-tls            Disable TLS pattern matcher
  -h                  Show this help
```

## 配置文件格式

配置文件位于 `config/fdir_rules.conf`，格式为：
```
# 注释行以#开头
id=type,priority,queue,参数...

# 示例：
100=ipv4,10,0,proto=tcp
101=http,20,1,dport=80,method=GET
102=tls,20,2,dport=443
```

### 支持的流量类型
- `ipv4`: IPv4流量
- `ipv6`: IPv6流量
- `tcp`: TCP流量
- `udp`: UDP流量
- `vlan`: VLAN流量
- `http`: HTTP流量
- `tls`: TLS流量

### 支持的匹配参数
- `src/dst`: IP地址（支持CIDR格式）
- `sport/dport`: 端口号
- `proto`: 协议号（TCP=6, UDP=17）
- `vlan`: VLAN ID
- `method`: HTTP方法（GET, POST等）
- `action`: 动作（drop表示丢弃）

## 默认Flow规则

如果没有指定配置文件，程序会创建以下默认规则：

1. IPv4 TCP流量 → 队列0
2. HTTP流量（端口80） → 队列1
3. HTTPS/TLS流量（端口443） → 队列2
4. DNS流量（端口53） → 队列3

## 统计信息

程序运行时会定期输出以下统计信息：

- FDIR总体统计
  - 接收/发送包数
  - Flow匹配次数
  - 各队列统计

- 数据包处理统计
  - 各类型数据包数量
  - 处理延迟
  - 错误统计

- 模式匹配统计
  - HTTP检测次数
  - TLS检测次数
  - 平均匹配时间

## 代码结构

```
fdir_demo/
├── CMakeLists.txt          # CMake构建配置
├── main.c                   # 主程序入口
├── include/                 # 头文件目录
│   ├── fdir_core.h         # FDIR核心功能
│   ├── flow_manager.h      # Flow规则管理
│   ├── packet_processor.h  # 数据包处理
│   ├── pattern_matcher.h   # 模式匹配
│   ├── dpdk_utils.h        # DPDK工具函数
│   └── fdir_config.h       # 配置定义
├── src/                     # 源文件目录
│   ├── fdir_core.c         # FDIR核心实现
│   ├── flow_manager.c      # Flow规则管理实现
│   ├── packet_processor.c  # 数据包处理实现
│   ├── pattern_matcher.c   # 模式匹配实现
│   └── dpdk_utils.c        # DPDK工具函数实现
├── config/                  # 配置文件目录
│   └── fdir_rules.conf     # Flow规则配置
└── README.md               # 项目说明
```

## 核心模块说明

### 1. FDIR Core (fdir_core)
- DPDK初始化和端口配置
- rte_flow规则创建和管理
- 硬件流量分发
- 统计信息收集

### 2. Flow Manager (flow_manager)
- Flow规则的生命周期管理
- 规则验证和优先级管理
- 批量操作支持

### 3. Packet Processor (packet_processor)
- 数据包接收和解析
- L2-L4层协议解析
- 队列管理

### 4. Pattern Matcher (pattern_matcher)
- HTTP协议识别
- TLS协议识别
- 自定义模式匹配

## 性能优化建议

1. **CPU亲和性**
   - 将处理线程绑定到特定CPU核心
   - 使用NUMA感知的内存分配

2. **队列配置**
   - 根据网卡能力配置合适的队列数
   - 启用RSS进行负载均衡

3. **批处理**
   - 使用burst模式接收数据包
   - 调整burst大小以获得最佳性能

4. **硬件卸载**
   - 启用网卡的checksum offload
   - 使用硬件Flow Director

## 调试

启用调试模式：
```bash
make -j CMAKE_BUILD_TYPE=Debug
```

或修改 `fdir_config.h` 中的 `FDIR_DEBUG` 宏。

## 注意事项

1. 程序需要root权限运行
2. 确保网卡支持Flow Director功能
3. 根据实际硬件调整队列数量
4. 大流量时注意内存使用

## 故障排除

1. **EAL初始化失败**
   - 检查hugepages配置
   - 确认网卡绑定到DPDK

2. **Flow创建失败**
   - 检查网卡硬件支持
   - 验证规则参数有效性

3. **性能问题**
   - 检查CPU频率设置
   - 确认队列配置合理

## 许可证

本程序采用BSD-3-Clause许可证。