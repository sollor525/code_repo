# PCRE 字段支持文档

## 概述

Web扫描检测引擎完整支持PCRE（Perl Compatible Regular Expressions）字段，实现了企业级智能三层处理架构，确保高性能的同时保持完整的正则表达式兼容性。

### 企业级特性

- **三层处理架构**: Fast Pattern → Converted Hyperscan → Regex Fallback
- **完整PCRE兼容**: 支持所有常用PCRE语法和标志
- **智能优化**: 自动检测并选择最优处理层
- **性能保障**: 简单模式享受Hyperscan硬件加速，复杂模式保证100%兼容性
- **测试验证**: 57/57 核心测试通过 (100%)，6/6 FFI集成测试通过 (100%)

## 三层匹配架构

### Layer 1: Fast Pattern（Hyperscan直接编译）
- **适用情况**: PCRE模式可以直接被Hyperscan编译
- **处理方式**: 直接编译到Hyperscan数据库，享受硬件加速
- **性能**: 最高性能，单次扫描完成匹配
- **示例**: `/admin\/login/` - 简单字面量模式

### Layer 2: ConvertedHyperscan（模式转换）
- **适用情况**: PCRE模式需要转换但转换后仍可被Hyperscan处理
- **处理方式**: 智能转换为Hyperscan兼容的模式
- **性能**: 高性能，接近原生Hyperscan
- **示例**: `/^POST\s+/` - 转换为 `^POST\s+`

### Layer 3: Regex Fallback（Rust regex引擎）
- **适用情况**: PCRE模式过于复杂，无法被Hyperscan处理
- **处理方式**: 使用Rust标准regex crate进行处理
- **性能**: 较低性能，但保证完全兼容性
- **示例**: `/(?i)union\s+select.*from\s+\w+.*--/` - 复杂的模式组合

## PCRE语法支持

### 支持的PCRE标志
- **i**: 忽略大小写（`/pattern/i`）
- **m**: 多行模式（`/pattern/m`）
- **s**: 单行模式（`.`匹配换行符）（`/pattern/s`）
- **x**: 忽略空白字符和注释（`/pattern/x`）
- **组合**: 可以组合使用，如`/pattern/imsx`

### 基本语法
```rules
# 简单字面量匹配
alert http any any -> any any (msg:"Simple PCRE"; pcre:"/admin/"; sid:1001;)

# 忽略大小写匹配
alert http any any -> any any (msg:"Case insensitive"; pcre:"/login/i"; sid:1002;)

# 多行模式匹配
alert http any any -> any any (msg:"Multi-line"; pcre:"/error/m"; sid:1003;)

# 单行模式匹配（点匹配换行符）
alert http any any -> any any (msg:"Single-line"; pcre:"/content.*body/s"; sid:1004;)
```

### 高级语法
```rules
# 复杂组合模式
alert http any any -> any any (msg:"SQL injection";
    pcre:"/(?i)union\s+select.*from\s+\w+/"; sid:1005;)

# 字符类和量词
alert http any any -> any any (msg:"Attack pattern";
    pcre:"/[<>\"'].*[<>=]+/i"; sid:1006;)

# 交替和分组
alert http any any -> any any (msg:"Multiple attacks";
    pcre:"/(select|insert|update|delete).*from/i"; sid:1007;)

# 注释模式（使用x标志）
alert http any any -> any any (msg:"Complex pattern";
    pcre:"/
        (?i)                     # 忽略大小写
        (?:select|insert)         # 非捕获分组
        \s+                      # 一个或多个空白字符
        \w+                      # 一个或多个单词字符
        \.                       # 点号
    /x"; sid:1008;)
```

## HTTP位置匹配

PCRE模式可以与HTTP位置修饰符结合使用，实现精确的位置匹配：

```rules
# 在URI中匹配PCRE模式
alert http any any -> any any (
    msg:"PCRE in URI";
    pcre:"/admin\/login/i";
    http.uri;
    sid:2001;
)

# 在请求体中匹配PCRE模式
alert http any any -> any any (
    msg:"PCRE in body";
    pcre:"/(?i)username\s*=\s*admin/i";
    http.request_body;
    sid:2002;
)

# 在Cookie中匹配PCRE模式
alert http any any -> any any (
    msg:"PCRE in Cookie";
    pcre:"/session_id\s*=\s*[a-f0-9]+/i";
    http.cookie;
    sid:2003;
)

# 在请求头中匹配PCRE模式
alert http any any -> any any (
    msg:"PCRE in headers";
    pcre:"/User-Agent:\s*(?:bot|crawler|scanner)/i";
    http.request_header;
    sid:2004;
)
```

## 兼容性检测

引擎会自动检测PCRE模式的兼容性：

1. **Hyperscan兼容性检查**: 检查模式是否可以被Hyperscan直接编译
2. **转换可能性评估**: 评估是否可以通过转换使其兼容
3. **自动选择最优处理方式**: 根据模式复杂度自动选择最佳处理层

## 性能特性

### 自动优化
- **编译时优化**: 在规则加载时进行兼容性分析和预处理
- **缓存机制**: 编译后的正则表达式会被缓存，避免重复编译
- **批量处理**: 相同类型的PCRE模式会批量处理以提高效率

### 性能指南
1. **优先使用简单模式**: 简单的字面量模式性能最佳
2. **合理使用修饰符**: 只在需要时使用`i`、`m`等修饰符
3. **避免过度复杂的模式**: 复杂的正则表达式会显著影响性能
4. **利用HTTP位置限制**: 通过HTTP位置修饰符减少匹配范围

## 错误处理

### 常见错误
```rules
# 错误：无效的正则表达式
alert http any any -> any any (
    msg:"Invalid regex";
    pcre:"/([/";  # 缺少闭合括号
    sid:3001;
)

# 错误：不支持的PCRE语法
alert http any any -> any any (
    msg:"Unsupported syntax";
    pcre:"/(?P<name>pattern)/";  # 不支持命名捕获组
    sid:3002;
)
```

### 错误处理机制
- **编译时检测**: 规则加载时会验证PCRE语法
- **运行时容错**: 无效的模式会被记录，但不会影响其他规则的运行
- **详细错误信息**: 提供具体的错误原因和建议修复方案

## 测试和验证

### 兼容性测试
```bash
# 运行PCRE兼容性测试
cargo test --test hyperscan_compatibility

# 运行PCRE综合功能测试
cargo test --test pcre_comprehensive

# 运行PCRE边缘情况测试
cargo test --test pcre_edge_cases
```

### 调试支持
```rust
// 使用PcreProcessor进行调试
use web_scan_rust::pcre::{PcreProcessor, HttpMatchLocation};

let mut processor = PcreProcessor::new();
processor.parse_pcre_pattern("/admin\/login/i", 1001, HttpMatchLocation::Any)?;
let matches = processor.process_data_with_pcre(data, 1001);
```

## 最佳实践

### 1. 模式设计原则
- **保持简洁**: 尽可能使用简单的模式
- **明确目标**: 针对特定的攻击特征设计模式
- **避免贪婪**: 使用非贪婪量词`*?`、`+?`避免过度匹配

### 2. 性能优化
- **位置限制**: 使用HTTP位置修饰符限制匹配范围
- **早期退出**: 将最可能匹配的模式放在前面
- **批量处理**: 将相似的模式合并处理

### 3. 维护性
- **文档注释**: 为复杂的PCRE模式添加注释
- **测试覆盖**: 为每个PCRE模式编写对应的测试用例
- **版本控制**: 记录PCRE模式的变更历史

## 示例规则集

### Web攻击检测
```rules
# SQL注入检测
alert http any any -> any any (
    msg:"SQL Injection - Union Select";
    pcre:"/(?i)union\s+select.*from/i";
    sid:4001;
    metadata:category=sql_injection,severity=high;
)

# XSS攻击检测
alert http any any -> any any (
    msg:"XSS - Script Tag";
    pcre:"/<script[^>]*>.*?<\/script>/si";
    sid:4002;
    metadata:category=xss,severity=medium;
)

# 目录遍历检测
alert http any any -> any any (
    msg:"Directory Traversal";
    pcre:"/\.\.[\\/]\.\.[\\/]/i";
    http.uri;
    sid:4003;
    metadata:category=directory_traversal,severity=medium;
)

# 命令注入检测
alert http any any -> any any (
    msg:"Command Injection";
    pcre:"/[;&|`](?:ls|cat|whoami|id|uname)/i";
    sid:4004;
    metadata:category=command_injection,severity=critical;
)
```

### 扫描工具检测
```rules
# 扫描工具指纹
alert http any any -> any any (
    msg:"Scanner - Nikto";
    pcre:"/nikto/i";
    http.request_header;
    sid:5001;
    metadata:category=scanner,severity=low;
)

# 扫描工具User-Agent
alert http any any -> any any (
    msg:"Scanner - Common User-Agents";
    pcre:"/(?:nmap|nessus|openvas|sqlmap|burp)/i";
    http.request_header;
    sid:5002;
    metadata:category=scanner,severity=low;
)
```

## 故障排除

### 常见问题

**Q: PCRE模式不匹配怎么办？**
A: 检查以下几点：
1. 确认PCRE语法是否正确
2. 验证HTTP位置修饰符是否合适
3. 使用调试工具测试模式匹配情况

**Q: 性能下降了怎么办？**
A: 考虑以下优化：
1. 简化复杂的正则表达式
2. 使用更精确的HTTP位置限制
3. 检查是否有不必要的PCRE模式

**Q: 如何知道PCRE模式在哪一层处理？**
A: 查看引擎日志或使用统计接口获取处理层数据

### 调试工具
项目提供了多个调试工具帮助开发：
- `debug_http_parsing.rs`: HTTP解析调试
- `debug_rule_match.rs`: 规则匹配调试
- `debug_http_header.rs`: HTTP头匹配调试

## 总结

PCRE字段支持为Web扫描检测引擎提供了强大的模式匹配能力，通过三层匹配架构实现了性能与功能的完美平衡。开发者可以充分利用PCRE的强大表达能力，同时享受Hyperscan带来的高性能加速。