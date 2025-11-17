# Web扫描检测引擎 - Rust实现

这是一个高性能的Web扫描检测引擎，使用Rust语言编写，提供FFI接口用于与C/C++代码集成。

## 项目概述

本项目是一个专门用于检测Web扫描攻击的安全工具，具有以下特点：

- **高性能**: 使用Rust语言编写，提供接近C语言的性能
- **内存安全**: 利用Rust的所有权系统，避免内存泄漏和悬空指针
- **线程安全**: 支持多线程并发处理，适合高流量环境
- **易于集成**: 提供完整的C语言FFI接口
- **可扩展**: 支持多种规则格式和协议类型
- **Hyperscan加速**: 可选的Intel Hyperscan高性能正则表达式引擎支持
- **分段数据包支持**: 支持TCP流重组和分段数据包处理

## 核心功能

### 1. 协议检测
- **HTTP检测**: 识别HTTP/1.0、HTTP/1.1请求和响应
- **HTTPS检测**: 识别TLS/SSL握手过程
- **HTTP/2检测**: 支持HTTP/2协议的前言检测
- **智能识别**: 基于内容特征的协议识别，置信度评估

### 2. 规则匹配
- **多种格式**: 支持JSON、TOML和Hyperscan/Snort格式的规则文件
- **正则表达式**: 支持复杂的模式匹配规则
- **Hyperscan加速**: 可选的Intel Hyperscan高性能匹配引擎
- **动作配置**: 支持告警、丢弃、重置等多种响应动作
- **元数据支持**: 每条规则可以包含分类、优先级等额外信息

### 3. 统计收集
- **性能监控**: 记录处理时间、吞吐量等性能指标
- **流量统计**: 统计各种协议的数据包数量
- **规则统计**: 记录规则匹配和动作执行情况
- **实时更新**: 支持实时统计信息查询

### 4. 分段数据包处理
- **流重组**: 支持TCP流的分段数据包重组
- **缓冲区管理**: 提供流数据缓冲区管理接口
- **完整检测**: 自动检测流数据是否完整
- **外部会话管理**: 会话管理由外部程序负责，库专注于检测

### 4. FFI接口
- **C语言兼容**: 提供完整的C语言函数接口
- **类型安全**: 使用Rust的类型系统确保接口安全
- **错误处理**: 统一的错误码和错误信息机制
- **内存管理**: 自动内存管理，无需手动释放

## 项目架构

```
web_scan_rust/
├── src/                    # 源代码目录
│   ├── lib.rs             # 库入口点，模块声明
│   ├── engine.rs          # 核心检测引擎
│   ├── protocol.rs        # 协议检测模块
│   ├── rules.rs           # 规则管理模块
│   ├── stats.rs           # 统计收集模块
│   ├── error.rs           # 错误处理模块
│   └── ffi.rs             # FFI接口模块
├── build.rs               # 构建脚本
├── cbindgen.toml          # C头文件生成配置
├── Cargo.toml             # 项目依赖配置
└── README.md              # 项目说明文档
```

### 模块说明

- **engine.rs**: 检测引擎的核心逻辑，协调各个模块工作
- **protocol.rs**: 负责识别网络数据包的协议类型
- **rules.rs**: 管理检测规则，支持规则加载、匹配和更新
- **stats.rs**: 收集和统计各种运行指标
- **error.rs**: 定义错误类型和错误处理机制
- **ffi.rs**: 提供C语言兼容的外部函数接口

## 安装和构建

### 系统要求
- Rust 1.70+ (推荐使用最新稳定版本)
- Cargo包管理器
- 支持的操作系统: Linux, macOS, Windows

### 构建步骤

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd web_scan_rust
   ```

2. **安装Hyperscan依赖（可选）**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libhyperscan-dev
   
   # CentOS/RHEL
   sudo yum install hyperscan-devel
   
   # macOS
   brew install hyperscan
   ```

3. **构建项目**
   ```bash
   # 普通构建
   cargo build --release
   
   # 启用Hyperscan支持的构建
   cargo build --release --features hyperscan
   ```

4. **运行测试**
   ```bash
   cargo test
   ```

5. **生成C头文件**
   ```bash
   cargo build
   # 头文件将生成在 target/include/ 目录下
   ```

### 构建产物

构建完成后，会生成以下文件：

- **动态库**: `target/release/libweb_scan_rust.so` (Linux) 或 `.dll` (Windows)
- **C头文件**: `target/include/web_scan_rust.h`
- **静态库**: `target/release/libweb_scan_rust.rlib`

## 使用方法

### C语言集成示例

```c
#include "web_scan_rust.h"
#include <stdio.h>
#include <string.h>

int main() {
    // 初始化引擎（启用Hyperscan）
    if (web_scan_rust_init_with_hyperscan(1) != 0) {
        printf("Failed to initialize engine\n");
        return -1;
    }
    
    // 检查Hyperscan状态
    if (web_scan_rust_is_hyperscan_enabled()) {
        printf("Hyperscan acceleration enabled\n");
    }
    
    // 加载规则文件（支持Hyperscan格式）
    if (web_scan_rust_load_rules("rules.rules") != 0) {
        printf("Failed to load rules\n");
        return -1;
    }
    
    // 处理单个数据包
    const char* payload = "GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    WebScanResult result;
    
    if (web_scan_rust_process_payload(
        (const uint8_t*)payload,
        strlen(payload),
        &result) == 0) {
        
        if (result.is_matched) {
            printf("Threat detected! Rule ID: %u, Action: %d\n",
                   result.rule_id, result.action);
        }
    }
    
    // 处理分段数据包
    uint8_t stream_buffer[4096];
    uint32_t stream_len = 0;
    
    // 第一个分段
    const char* segment1 = "GET /admin/";
    int ret = web_scan_rust_process_segmented_payload(
        (const uint8_t*)segment1,
        strlen(segment1),
        stream_buffer,
        stream_len,
        sizeof(stream_buffer),
        0, // 不完整
        &result,
        &stream_len
    );
    
    if (ret == 1) {
        printf("Need more data for complete packet\n");
    }
    
    // 第二个分段（完整）
    const char* segment2 = "login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    ret = web_scan_rust_process_segmented_payload(
        (const uint8_t*)segment2,
        strlen(segment2),
        stream_buffer,
        stream_len,
        sizeof(stream_buffer),
        1, // 完整
        &result,
        &stream_len
    );
    
    if (ret == 0 && result.is_matched) {
        printf("Threat detected in segmented packet! Rule ID: %u\n", result.rule_id);
    }
    
    // 获取统计信息
    WebScanStats stats;
    if (web_scan_rust_get_stats(&stats) == 0) {
        printf("Processed packets: %lu\n", stats.packets_processed);
        printf("Matched packets: %lu\n", stats.packets_matched);
    }
    
    return 0;
}
```

### Rust语言使用示例

```rust
use web_scan_rust::{WebScanEngine, WebScanResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建检测引擎
    let mut engine = WebScanEngine::new();
    
    // 加载规则文件
    engine.init_with_rules("rules.json")?;
    
    // 处理数据包
    let payload = b"GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let result = engine.process_payload(payload)?;
    
    if result.is_matched {
        println!("威胁检测到！规则ID: {}, 动作: {:?}", 
                 result.rule_id, result.action);
    }
    
    // 获取统计信息
    let stats = engine.get_stats();
    println!("已处理数据包: {}", stats.packets_processed);
    println!("匹配数据包: {}", stats.packets_matched);
    
    Ok(())
}
```

## 规则文件格式

### JSON格式示例

```json
{
  "rules": [
    {
      "id": 1001,
      "action": "alert",
      "message": "管理员登录尝试",
      "pattern": "/admin/",
      "metadata": {
        "category": "access_control",
        "severity": "high"
      }
    },
    {
      "id": 1002,
      "action": "drop",
      "message": "SQL注入攻击",
      "pattern": "union\\s+select",
      "metadata": {
        "category": "injection",
        "severity": "critical"
      }
    }
  ]
}
```

### TOML格式示例

```toml
[[rules]]
id = 1001
action = "alert"
message = "管理员登录尝试"
pattern = "/admin/"
metadata = { category = "access_control", severity = "high" }

[[rules]]
id = 1002
action = "drop"
message = "SQL注入攻击"
pattern = "union\\s+select"
metadata = { category = "injection", severity = "critical" }
```

### Hyperscan/Snort格式示例

```rules
# 管理员访问检测
alert http any any -> any any (msg:"Admin access"; content:"/admin/"; sid:1001;)

# SQL注入检测
drop http any any -> any any (msg:"SQL injection"; content:"union select"; sid:1002;)

# XSS攻击检测
alert http any any -> any any (msg:"XSS attempt"; content:"<script>"; sid:1003;)
```

## 性能特性

### 优化策略
- **零拷贝**: 尽可能避免不必要的数据复制
- **原子操作**: 使用原子类型实现无锁统计
- **内存池**: 高效的内存分配和回收
- **SIMD优化**: 利用CPU向量指令加速字符串处理

### 性能指标
- **吞吐量**: 支持每秒数万数据包的处理
- **延迟**: 单包处理延迟通常在微秒级别
- **内存使用**: 内存占用随规则数量线性增长
- **CPU使用**: 高效利用多核CPU资源

## 错误处理

### 错误类型
- **协议检测错误**: 无法识别协议类型
- **规则解析错误**: 规则文件格式错误
- **配置错误**: 引擎配置参数无效
- **IO错误**: 文件读写失败
- **内存错误**: 内存分配失败

### 错误码
- `0`: 成功
- `-1`: 协议检测失败
- `-2`: 规则解析错误
- `-3`: Hyperscan错误
- `-4`: 配置错误
- `-5`: IO错误
- `-6`: JSON解析错误
- `-7`: 无效输入
- `-8`: 引擎未初始化
- `-9`: 内存分配失败

## 测试和验证

### 单元测试
```bash
# 运行所有测试
cargo test

# 运行特定模块测试
cargo test --lib protocol

# 运行测试并显示输出
cargo test -- --nocapture
```

### 性能测试
```bash
# 运行基准测试
cargo bench

# 运行特定基准测试
cargo bench detection_bench
```

### 集成测试
```bash
# 运行集成测试
cargo test --test integration_tests
```

## 贡献指南

### 开发环境设置
1. 安装Rust工具链
2. 克隆项目仓库
3. 运行测试确保环境正常
4. 创建功能分支

### 代码规范
- 遵循Rust官方代码风格
- 所有公共API必须有文档注释
- 新功能必须包含测试用例
- 提交前运行完整的测试套件

### 提交规范
- 使用清晰的提交信息
- 每个提交只包含一个逻辑变更
- 包含相关的测试和文档更新

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 联系方式

- 项目维护者: npatch team
- 问题反馈: 请使用GitHub Issues
- 功能建议: 欢迎提交Pull Request

## 更新日志

### v0.1.0 (当前版本)
- 初始版本发布
- 支持HTTP/HTTPS/HTTP2协议检测
- 支持JSON和TOML规则格式
- 提供完整的C语言FFI接口
- 包含统计收集和性能监控功能

## 相关资源

- [Rust官方文档](https://doc.rust-lang.org/)
- [Cargo包管理器](https://doc.rust-lang.org/cargo/)
- [FFI最佳实践](https://doc.rust-lang.org/nomicon/ffi.html)
- [性能优化指南](https://doc.rust-lang.org/rustc/profile-guided-optimization.html)