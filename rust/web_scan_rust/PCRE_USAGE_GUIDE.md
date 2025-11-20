# PCRE字段使用指南

## 概述

本项目现已支持PCRE（Perl Compatible Regular Expressions）字段，为Web扫描检测引擎提供了强大的模式匹配能力。PCRE支持分层处理机制，根据模式复杂度自动选择最优的匹配方式。

## 功能特性

### 🎯 分层处理机制

1. **Hyperscan直接匹配**（高性能）
   - 兼容的正则直接编译为Hyperscan规则
   - 利用硬件加速，适用于大规模流量检测
   - 支持常用的正则表达式语法

2. **转换后匹配**（中等性能）
   - 不兼容的正则尝试转换为Hyperscan兼容格式
   - 保留原有匹配语义，提升处理效率

3. **Regex fallback**（低性能）
   - 无法转换的使用regex crate进行匹配
   - 支持完整的PCRE特性，确保兼容性

### 📝 支持的PCRE语法

#### 基本格式
```suricata
# 标准格式：/pattern/flags
pcre:"/pattern/i"

# 简化格式：直接使用字符串
pcre:"pattern"
```

#### 支持的标志
- `i` - 忽略大小写匹配
- `s` - 单行模式（`.`匹配换行符）
- `m` - 多行模式（`^`和`$`匹配行边界）
- `x` - 扩展模式（忽略空白和注释）

#### 支持的正则特性
- **基础元字符**：`.`, `*`, `+`, `?`, `|`
- **字符类**：`[abc]`, `[^abc]`, `[a-z0-9]`
- **量词**：`{n}`, `{n,m}`, `{n,}`, `{,m}`
- **锚点**：`^`, `$`
- **简写字符类**：`\d`, `\w`, `\s`, `\D`, `\W`, `\S`
- **分组**：`(pattern)`, `(pattern1|pattern2)`
- **转义字符**：`\.`, `\*`, `\+`, `\?`, `\[`, `\]`, `\(`, `\)`

## 使用示例

### 基本PCRE规则

```suricata
# 简单匹配
alert http any any -> any any (
    msg:"Basic PCRE test";
    pcre:"/test/i";
    sid:1001;
)

# HTTP位置限制
alert http any any -> any any (
    msg:"PCRE in URI";
    pcre:"/admin|administrator/";
    http.uri;
    sid:1002;
)
```

### 安全检测规则

```suricata
# SQL注入检测
alert http any any -> any any (
    msg:"SQL Injection attempt";
    pcre:"/(union|select|insert|update|delete).*from/i";
    http.request_body;
    sid:1003;
)

# XSS攻击检测
alert http any any -> any any (
    msg:"XSS attack attempt";
    pcre:"/<script[^>]*>.*?</script>/i";
    http.request_body;
    sid:1004;
)

# 路径遍历检测
alert http any any -> any any (
    msg:"Path traversal attempt";
    pcre:"/\.\.[\/\\\\]/i";
    http.uri;
    sid:1005;
)
```

### 复杂模式示例

```suricata
# 邮箱地址检测
alert http any any -> any any (
    msg:"Email address in request";
    pcre:"/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/";
    http.request_body;
    sid:1006;
)

# IP地址检测
alert http any any -> any any (
    msg:"IP address in URI";
    pcre:"/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/";
    http.uri;
    sid:1007;
)

# 日期格式检测
alert http any any -> any any (
    msg:"Date format detection";
    pcre:"/\d{4}-\d{2}-\d{2}/";
    http.request_body;
    sid:1008;
)
```

### 混合content和PCRE

```suricata
# 同时使用content和PCRE
alert http any any -> any any (
    msg:"Login attempt with password field";
    content:"login";
    pcre:"/password.*[a-zA-Z0-9]{8,}/i";
    http.request_body;
    sid:1009;
)
```

## 性能优化建议

### 1. 优先使用Hyperscan兼容模式

```suricata
# ✅ 推荐：Hyperscan兼容
pcre:"/admin|login|user/i"

# ⚠️  避免：需要fallback
pcre:"/(?<=user)admin/"
```

### 2. 合理使用HTTP位置限制

```suricata
# ✅ 推荐：限制在特定位置
pcre:"/admin/"; http.uri;

# ⚠️  避免：全文匹配（性能影响大）
pcre:"/admin/";
```

### 3. 使用适当的量词

```suricata
# ✅ 推荐：具体量词
pcre:"/\d{4}-\d{2}-\d{2}/"

# ⚠️  避免：过度通配符
pcre:"/.*admin.*"
```

## 测试用例

### 运行基础测试

```bash
# 运行PCRE模块测试
cargo test pcre::tests

# 运行规则系统测试
cargo test rules::tests
```

### 运行示例程序

```bash
# 基础PCRE测试
cargo run --example pcre_test

# HTTP流量检测测试
cargo run --example http_pcre_detection
```

### 性能基准测试

```bash
# 安装criterion基准测试工具
cargo install cargo-criterion

# 运行性能基准测试
cargo bench
```

## 编程接口

### PCRE处理器

```rust
use web_scan_rust::pcre::{PcreProcessor, PcreMatchType};

let mut processor = PcreProcessor::new();

// 处理PCRE模式
let result = processor.process_pcre_pattern(
    "/pattern/i",
    HttpMatchLocation::Any,
    false,  // startswith
    false,  // endswith
    None,   // distance
    None,   // depth
    None,   // offset
    None,   // within
)?;

let pcre_pattern = result;

// 检查匹配类型
match pcre_pattern.match_type {
    PcreMatchType::Hyperscan => println!("高性能Hyperscan匹配"),
    PcreMatchType::ConvertedHyperscan => println!("转换后的Hyperscan匹配"),
    PcreMatchType::RegexFallback => println!("Regex fallback匹配"),
}
```

### 规则匹配

```rust
use web_scan_rust::rules::RuleManager;

let mut rule_manager = RuleManager::new();

// 加载包含PCRE的规则文件
rule_manager.load_rules_from_file(Path::new("rules.pcre"))?;

// 执行检测
if let Some(rule) = rule_manager.match_content(http_data) {
    println!("检测到威胁: {}", rule.message);
}

// 检查是否有PCRE匹配
for (_, rule) in rule_manager.get_all_rules() {
    if rule.has_pcre_patterns() {
        if rule.pcre_matches(http_data) {
            println!("PCRE模式匹配: {}", rule.id);
        }
    }
}
```

## 故障排除

### 常见问题

1. **规则无法加载**
   - 检查PCRE语法是否正确
   - 确保规则文件格式符合Suricata规范

2. **性能问题**
   - 简化复杂的正则表达式
   - 使用HTTP位置限制减少匹配范围
   - 避免过度使用通配符

3. **匹配不准确**
   - 检查PCRE标志是否正确设置
   - 验证HTTP位置限制是否合适
   - 测试正则表达式的匹配行为

### 调试工具

```bash
# 启用调试日志
RUST_LOG=debug cargo run --example pcre_test

# 查看规则解析详情
RUST_LOG=debug cargo test pcre::tests
```

## 最佳实践

### 1. 模式设计
- 从简单模式开始，逐步增加复杂性
- 使用具体的匹配而非过度通用的模式
- 充分利用HTTP位置限制提高效率

### 2. 性能优化
- 优先使用Hyperscan兼容的语法
- 避免嵌套量词和复杂的回溯模式
- 合理使用量词限制匹配范围

### 3. 规则维护
- 定期测试和验证规则的有效性
- 监控匹配性能，优化慢速规则
- 文档化复杂模式的设计意图

### 4. 错误处理
- 验证PCRE语法的正确性
- 处理编译失败的情况
- 提供降级匹配策略

## 版本兼容性

- **当前版本**：支持基础PCRE功能和简化实现
- **完整版本**：将支持完整的Hyperscan集成和高级PCRE特性
- **向后兼容**：现有的content规则继续有效

## 贡献指南

欢迎提交问题报告和改进建议：

1. **报告问题**：提供详细的错误信息和重现步骤
2. **功能请求**：描述期望的功能和使用场景
3. **性能问题**：提供测试数据和性能基准
4. **文档改进**：修正错误或补充使用示例

---

*本指南持续更新，请查看最新版本的文档以获取最新信息。*