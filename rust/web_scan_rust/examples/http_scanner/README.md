# HTTP扫描检测器 - C程序实现

这是一个基于Web扫描检测引擎的C语言HTTP流量安全检测程序，支持加载Suricata规则并分析pcap文件中的HTTP攻击流量。

## 项目特性

- ✅ **高性能检测**: 基于Rust实现的Web扫描检测引擎
- ✅ **Hyperscan加速**: 集成Intel Hyperscan高性能模式匹配引擎
- ✅ **PCRE支持**: 完整的PCRE正则表达式支持，三层匹配架构
- ✅ **libpcap集成**: 完整的pcap文件解析和HTTP流量提取
- ✅ **Suricata兼容**: 支持标准Suricata规则格式
- ✅ **实时统计**: 检测性能和攻击统计实时显示
- ✅ **会话管理**: 支持分段数据包的TCP流重组
- ✅ **CMake构建**: 跨平台构建系统

## 目录结构

```
examples/http_scanner/
├── src/
│   └── main.c              # 主程序源码
├── rules/
│   ├── web_attacks.rules   # Web攻击检测规则
│   └── pcre_advanced.rules # PCRE高级检测规则
├── build/                  # 构建输出目录
├── CMakeLists.txt         # CMake构建配置
├── run_scanner.sh.in      # 启动脚本模板
├── build.sh               # 自动构建脚本
└── README.md              # 本文档
```

## 系统要求

### 必需依赖
- **Rust 1.70+**: 用于编译Web扫描检测引擎
- **CMake 3.12+**: 用于构建C程序
- **GCC/Clang**: C编译器，支持C99标准
- **Intel Hyperscan**: 高性能模式匹配引擎

### 可选依赖
- **libpcap-dev**: 用于pcap文件处理
  ```bash
  # Ubuntu/Debian
  sudo apt-get install libpcap-dev

  # CentOS/RHEL
  sudo yum install libpcap-devel

  # macOS
  brew install libpcap
  ```

## 快速开始

### 1. 自动构建（推荐）

```bash
# 进入项目目录
cd examples/http_scanner

# 运行自动构建脚本
./build.sh
```

### 2. 手动构建

#### 步骤1: 设置环境变量
```bash
export PKG_CONFIG_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/root/workspace/vpp-ips/3rd-dep/hyperscan/hyperscan:$LD_LIBRARY_PATH"
```

#### 步骤2: 构建Rust库
```bash
# 在项目根目录执行
cd ../..
cargo build --release
```

#### 步骤3: 构建C程序
```bash
# 进入http_scanner目录
cd examples/http_scanner
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## 使用方法

### 命令行选项

```bash
./http_scanner [选项]

选项:
  -r, --rules <dir>      规则文件目录 (默认: ./rules)
  -p, --pcap <file>      要处理的pcap文件
  -h, --help             显示帮助信息
  -v, --version          显示版本信息
```

### 使用示例

#### 1. 显示帮助信息
```bash
./http_scanner --help
```

#### 2. 显示版本信息
```bash
./http_scanner --version
```

#### 3. 加载规则并分析pcap文件
```bash
./http_scanner --rules ./rules --pcap /path/to/traffic.pcap
```

#### 4. 使用启动脚本（推荐）
```bash
# 启动脚本会自动设置库路径
./build/run_scanner.sh --rules ../rules --pcap sample.pcap
```

## 规则文件格式

### 基础规则格式
```rules
# 管理员访问检测
alert http any any -> any any (
    msg:"管理员面板访问";
    content:"/admin";
    http.uri;
    sid:1001;
)

# SQL注入检测
alert http any any -> any any (
    msg:"SQL注入攻击";
    content:"union";
    http.request_body;
    content:"select";
    http.request_body;
    distance:10;
    sid:2001;
)
```

### PCRE高级规则
```rules
# 复杂SQL注入检测
alert http any any -> any any (
    msg:"PCRE检测 - 复杂SQL注入";
    pcre:"/(?i)(?:select|insert|update|delete)\s+.*\s+from\s+\w+/i";
    http.request_body;
    sid:7001;
)

# XSS攻击检测
alert http any any -> any any (
    msg:"PCRE检测 - 完整XSS脚本";
    pcre:"/<script[^>]*>.*?<\/script>/si";
    http.request_body;
    sid:8001;
)
```

## 检测输出示例

```
🚀 HTTP扫描检测器启动
版本: 1.0.0
基于Web扫描检测引擎 (Rust实现)
========================================

正在初始化检测引擎...
✅ 引擎初始化成功
✅ Hyperscan加速已启用 (默认模式)

正在加载规则文件: ./rules
✅ 规则加载成功

📋 已加载的规则信息:
========================================
规则已成功加载并激活
检测引擎已初始化完成
========================================

正在处理pcap文件: /path/to/traffic.pcap
✅ 成功加载pcap文件，开始分析HTTP流量...
过滤器: tcp port 80 or tcp port 8080 or tcp port 8000
=========================================

🚨 [攻击检测] 数据包 #124
规则ID: 2001
动作类型: ALERT
处理时间: 0.045 ms
运行时间: 2.34 秒
检测率: 0.81% (匹配/总包数)
=========================================
攻击载荷 (前64字节): POST /login.php HTTP/1.1\r\nHost: example.com\r\nContent-Type: applic

✅ pcap文件处理完成，共处理 15234 个数据包

📊 统计信息:
========================================
处理数据包总数: 15234
匹配数据包数: 124
匹配率: 0.81%
总处理时间: 687.234 ms
平均处理时间: 0.045074 ms/包
=========================================
```

## 性能特性

### 三层匹配架构
1. **Fast Pattern**: HTTP header中的快速模式匹配
2. **Normal Content**: Hyperscan完全模式匹配
3. **PCRE/Regex Fallback**: 复杂正则表达式匹配

### 性能指标
- **吞吐量**: 每秒处理数万个HTTP数据包
- **延迟**: 单包处理延迟在微秒级别
- **内存效率**: 零拷贝设计，智能会话管理
- **并发安全**: 线程安全，支持多线程环境

## 故障排除

### 常见问题

#### 1. 找不到libweb_scan_rust.so
```bash
# 设置库路径
export LD_LIBRARY_PATH="/path/to/web_scan_rust/target/release:$LD_LIBRARY_PATH"

# 或者使用启动脚本（会自动设置路径）
./build/run_scanner.sh
```

#### 2. 找不到Hyperscan库
```bash
# 检查Hyperscan是否安装
pkg-config --modversion hyperscan

# 设置Hyperscan路径
export PKG_CONFIG_PATH="/path/to/hyperscan:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="/path/to/hyperscan:$LD_LIBRARY_PATH"
```

#### 3. libpcap功能不可用
```bash
# 安装libpcap开发库
sudo apt-get install libpcap-dev

# 重新编译
./build.sh
```

#### 4. 规则加载失败
```bash
# 检查规则文件语法
# 确保规则文件是有效的Suricata格式
# 查看详细错误信息
./http_scanner --rules ./rules --pcap test.pcap
```

### 调试方法

#### 启用详细输出
```bash
# 编译时启用调试模式
cmake .. -DCMAKE_BUILD_TYPE=Debug

# 运行时查看详细日志
RUST_LOG=debug ./http_scanner --rules ./rules --pcap test.pcap
```

#### 检查规则语法
```bash
# 使用项目内置的规则测试工具
cd ../..
cargo test --test integration_tests
```

## 开发指南

### 添加新规则
1. 在`rules/`目录下创建新的`.rules`文件
2. 使用标准Suricata语法编写规则
3. 支持content和pcre模式
4. 重启程序加载新规则

### 扩展功能
- 修改`src/main.c`添加新的数据包处理逻辑
- 使用WebScanEngine的FFI接口
- 参考`doc/API.md`了解完整API

### 性能优化
- 调整Hyperscan编译参数
- 优化规则设计，合理使用Fast Pattern
- 考虑使用更强大的硬件加速

## 许可证

本项目遵循MIT许可证，详见根目录LICENSE文件。

## 联系方式

- 项目主页: [GitHub Repository]
- 问题反馈: [GitHub Issues]
- 文档参考: [doc/](../../doc/)目录下的详细文档

## 更新日志

### v1.0.0 (当前版本)
- ✅ 完整的HTTP流量检测功能
- ✅ PCRE正则表达式支持
- ✅ libpcap集成
- ✅ CMake构建系统
- ✅ 实时统计显示
- ✅ Hyperscan高性能加速