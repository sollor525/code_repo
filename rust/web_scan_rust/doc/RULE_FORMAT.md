# 规则格式规范和支持特性

本文档详细说明Web Scan Rust引擎支持的规则格式要求、语法规范以及当前不支持的Suricata特性。

## 版本信息

- **引擎版本**: v0.1.0
- **兼容性**: Suricata/Snort基本规则语法兼容
- **测试状态**: 经过26个集成测试验证
- **优先级**: 生产级规则处理，专注于Web安全检测

## 概述

Web Scan Rust引擎支持基于Suricata/Snort语法的Web检测规则，专注于HTTP协议的Web攻击检测。引擎实现了高效的模式匹配和协议解析，但为了性能和专注性，某些高级特性暂未支持。

## 支持的规则格式

### 基本语法结构

```
alert <protocol> <source_ip> <source_port> -> <dest_ip> <dest_port> (options;)
```

#### 必需字段
- **action**: `alert` (告警), `drop` (丢弃), `reset` (重置)
- **protocol**: `http` (HTTP协议)
- **IP地址**: `any` (任意地址) 或具体IP
- **端口**: `any` (任意端口) 或具体端口
- **sid**: 规则ID (必须唯一)
- **msg**: 规则描述信息

### 完整支持的选项

#### 1. 基础选项
```snort
# 必需选项
sid:1001;                    # 规则唯一标识符
msg:"Rule description";      # 规则描述信息

# 可选选项
rev:1;                       # 规则修订版本
gid:1;                       # 规则组ID
priority:1;                  # 规则优先级
classification:web-attack;    # 攻击分类
metadata:category web,severity high;  # 元数据
```

#### 2. Content选项 (核心功能)
```snort
# 基本content匹配
content:"admin";             # 匹配文本内容
content:"<script>"; nocase;  # 不区分大小写匹配

# 支持的修饰符
startswith;                  # 必须在数据开始位置匹配
endswith;                    # 必须在数据结束位置匹配
depth:100;                   # 匹配深度限制
offset:50;                   # 匹配起始偏移
within:20;                   # 匹配长度限制
distance:10;                 # 距离前一个匹配的距离
```

#### 3. PCRE选项 (高级功能) ⭐ NEW
```snort
# 基本PCRE模式
pcre:"/admin\/login/i";           # 忽略大小写匹配

# PCRE + HTTP位置匹配
pcre:"/union\s+select/i"; http.request_body;  # 在请求体中匹配SQL注入

# 高级PCRE语法
pcre:"/(?i)(?:select|insert|update)\s+\w+\s+from/";  # 复杂的SQL注入模式

# 多行模式
pcre:"/error.*stack/m";         # 多行匹配错误和堆栈跟踪

# 单行模式（点匹配换行符）
pcre:"/content.*body/s";        # 点字符匹配换行符

# 扩展模式（支持注释和空白）
pcre:"
    /(?i)                       # 忽略大小写
    (?:attack|malware)          # 非捕获分组
    \s+                         # 空白字符
    pattern/x";
```

#### 4. PCRE标志支持 ⭐ NEW
- **i**: 忽略大小写 (`/pattern/i`)
- **m**: 多行模式 (`/pattern/m`)
- **s**: 单行模式 (`/pattern/s`)
- **x**: 扩展模式 (`/pattern/x`)
- **组合**: 可以组合使用，如`/pattern/imsx`

#### 5. HTTP位置修饰符 (完全支持)
```snort
# HTTP请求匹配
content:"GET"; http.method;           # HTTP方法匹配
content:"/admin"; http.uri;          # URI路径匹配
content:"session"; http.cookie;       # Cookie匹配
content:"User-Agent"; http.request_header;   # 请求头匹配
content:"password"; http.request_body;     # 请求体匹配

# HTTP响应匹配 (支持但主要用于request)
content:"200"; http.stat_code;        # HTTP状态码匹配
content:"Server"; http.response_header; # 响应头匹配
content:"success"; http.response_body;   # 响应体匹配
```

### JSON格式规则 (支持)
```json
{
  "rules": [
    {
      "id": 1001,
      "action": "alert",
      "message": "Admin access attempt",
      "pattern": "/admin/",
      "metadata": {
        "category": "access_control",
        "severity": "high",
        "description": "Detects admin panel access"
      }
    },
    {
      "id": 1002,
      "action": "drop",
      "message": "SQL injection attempt",
      "pattern": "union.*select",
      "is_regex": true,
      "metadata": {
        "category": "injection",
        "severity": "critical"
      }
    }
  ]
}
```

### TOML格式规则 (支持)
```toml
[[rules]]
id = 1001
action = "alert"
message = "Admin access attempt"
pattern = "/admin/"
metadata = { category = "access_control", severity = "high" }

[[rules]]
id = 1002
action = "drop"
message = "SQL injection attempt"
pattern = "union.*select"
is_regex = true
metadata = { category = "injection", severity = "critical" }
```

## 规则示例

### 基础Web检测规则
```snort
# 1. 管理员路径访问检测
alert http any any -> any any (msg:"Admin panel access"; content:"/admin"; http.uri; sid:1001;)

# 2. SQL注入检测
alert http any any -> any any (msg:"SQL injection"; content:"union"; content:"select"; http.request_body; distance:5; sid:1002;)

# 3. XSS攻击检测
alert http any any -> any any (msg:"XSS attempt"; content:"<script"; http.request_body; nocase; sid:1003;)
```

### PCRE高级检测规则 ⭐ NEW
```snort
# 4. 复杂SQL注入检测（PCRE）
alert http any any -> any any (
    msg:"Complex SQL injection";
    pcre:"/(?i)(?:select|insert|update|delete)\s+\w+\s+from\s+\w+/";
    http.request_body;
    sid:1004;
)

# 5. XSS攻击检测（PCRE）
alert http any any -> any any (
    msg:"XSS attack via script";
    pcre:"/<script[^>]*>.*?<\/script>/si";
    sid:1005;
)

# 6. 目录遍历攻击检测（PCRE）
alert http any any -> any any (
    msg:"Directory traversal";
    pcre:"/\.\.[\\/]\.\.[\\/]/i";
    http.uri;
    sid:1006;
)

# 7. 命令注入检测（PCRE）
alert http any any -> any any (
    msg:"Command injection";
    pcre:"/[;&|`](?:ls|cat|whoami|id|uname|pwd)/i";
    sid:1007;
)

# 8. 扫描工具指纹检测（PCRE）
alert http any any -> any any (
    msg:"Scanner fingerprint";
    pcre:"/(?:nikto|nmap|nessus|sqlmap|burp|openvas)/i";
    http.request_header;
    sid:1008;
)
```

### 复杂多Pattern规则
```snort
# 4. 文件上传漏洞检测
alert http any any -> any any (
    msg:"File upload attempt";
    content:"POST"; http.method;
    content:"upload"; http.uri;
    content:"multipart/form-data"; http.request_header;
    content:".php"; http.request_body;
    sid:1004;
)

# 5. 目录遍历攻击检测
alert http any any -> any any (
    msg:"Directory traversal";
    content:"../"; http.uri;
    content:"passwd"; http.request_body;
    distance:10;
    sid:1005;
)
```

### 使用修饰符的规则
```snort
# 6. 精确匹配规则
alert http any any -> any any (
    msg:"Exact admin access";
    content:"GET"; http.method;
    content:"/admin/login.php"; http.uri; startswith;
    content:"HTTP/1.1"; http.request_header; endswith;
    sid:1006;
)

# 7. 带深度和偏移的规则
alert http any any -> any any (
    msg:"Hidden parameter detection";
    content:"admin"; http.request_body; depth:100;
    content:"true"; http.request_body; offset:10; within:20;
    sid:1007;
)
```

## 当前不支持的Suricata特性

### 1. 高级协议特性
```snort
# ❌ 不支持 - FTP协议检测
alert ftp any any -> any any (msg:"FTP access"; content:"USER"; sid:2001;)

# ❌ 不支持 - DNS协议检测
alert dns any any -> any any (msg:"DNS query"; content:"google"; sid:2002;)

# ❌ 不支持 - TLS协议特定检测
alert tls any any -> any any (msg:"TLS handshake"; content:"TLS"; sid:2003;)
```

### 2. 复杂Flow选项
```snort
# ❌ 不支持 - 流状态检测
alert http any any -> any any (msg:"Flow tracking"; flow:to_server,established; sid:2004;)

# ❌ 不支持 - 流重新组装
alert http any any -> any any (msg:"Stream reassembly"; stream_reassemble; sid:2005;)

# ❌ 不支持 - TCP标志匹配
alert tcp any any -> any any (msg:"TCP flags"; flags:SYN,ACK; sid:2006;)
```

### 3. 高级Content特性
```snort
# ❌ 不支持 - 正则表达式内容
alert http any any -> any any (msg:"Regex content"; pcre:"/user\s*login/i"; sid:2007;)

# ❌ 不支持 - 字节码检测
alert http any any -> any any (msg:"Bytecode detection"; byte_test:1,!,0,0; sid:2008;)

# ❌ 不支持 - 字节跳跃
alert http any any -> any any (msg:"Byte jump"; byte_jump:2,0,relative; sid:2009;)

# ❌ 不支持 - isdataat检测
alert http any any -> any any (msg:"Data at position"; isdataat:100,relative; sid:2010;)
```

### 4. 服务器/客户端检测
```snort
# ❌ 不支持 - 服务器特征检测
http_server_msg;

# ❌ 不支持 - 客户端特征检测
http_client_body;

# ❌ 不支持 - URI编码检测
http_uri;

# ❌ 不支持 - 原始HTTP检测
http_raw_uri;
```

### 5. 限制和缓冲区选项
```snort
# ❌ 不支持 - 数据包长度限制
dsize:>100;

# ❌ 不支持 - 检测缓冲区
detection_filter:track by_src, count 10, seconds 30;

# ❌ 不支持 - 速率限制
rate_filter:track by_src, count 5, seconds 10;
```

### 6. 文件检测和提取
```snort
# ❌ 不支持 - 文件检测
filemd5;
filesha1;
filesha256;

# ❌ 不支持 - 文件提取
filestore;

# ❌ 不支持 - HTTP文件提取
http_file_data;
```

### 7. IP和端口的高级特性
```snort
# ❌ 不支持 - IP列表
[192.168.1.0/24,10.0.0.0/8]

# ❌ 不支持 - 端口范围
any:[80:443]

# ❌ 不支持 - 排除端口
!80

# ❌ 不支持 - 动态IP变量
$HOME_NET
$EXTERNAL_NET
```

## 规则编写最佳实践

### 1. 优先使用HTTP位置修饰符
```snort
# ✅ 推荐 - 明确指定HTTP位置
content:"admin"; http.uri;

# ❌ 避免 - 笼统匹配
content:"admin";
```

### 2. 合理使用Fast Pattern
```snort
# ✅ 推荐 - 将最具区分度的pattern放在前面
alert http any any -> any any (
    msg:"Admin login detection";
    content:"POST"; http.method;
    content:"admin"; http.uri;
    content:"login"; http.uri;
    sid:3001;
)
```

### 3. 避免过度复杂的正则表达式
```snort
# ✅ 推荐 - 简单明确的pattern
content:"union"; http.request_body;
content:"select"; http.request_body; distance:10;

# ❌ 避免 - 过于复杂的正则
pcre:"/union\s+.*select\s+.*from/i";
```

### 4. 合理使用修饰符
```snort
# ✅ 推荐 - 有目的的修饰符使用
content:"GET"; http.method;
content:".php"; http.uri; endswith;

# ❌ 避免 - 不必要的修饰符
content:"test"; http.request_body; depth:1000; offset:0;
```

## 性能优化建议

### 1. Fast Pattern优化
- 将最有区分度的content放在第一位
- 优先使用HTTP header中的content作为Fast Pattern
- 避免过于通用的Fast Pattern

### 2. 规则分组
```snort
# ✅ 推荐 - 按功能分组规则
# Admin access rules
alert http any any -> any any (msg:"Admin panel"; content:"/admin"; http.uri; sid:4001;)
alert http any any -> any any (msg:"Admin login"; content:"login"; http.uri; sid:4002;)

# Injection rules
alert http any any -> any any (msg:"SQL injection"; content:"union"; http.request_body; sid:4011;)
alert http any any -> any any (msg:"XSS injection"; content:"<script"; http.request_body; sid:4012;)
```

### 3. 避免回溯
- 避免在请求体中进行大量文本搜索
- 优先使用HTTP header和URI中的pattern
- 合理使用depth和offset限制搜索范围

## 测试和验证

### 规则测试示例
```bash
# 1. 测试单个规则
echo "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n" | \
./test_engine --rules /tmp/test.rules

# 2. 测试分段数据
./test_segmented_rules --rules /tmp/test.rules --payload-file /tmp/http_request.txt

# 3. 性能测试
./benchmark_engine --rules /tmp/large_ruleset.rules --iterations 10000
```

### 规则验证检查清单
- [ ] 规则语法正确
- [ ] 使用支持的选项和修饰符
- [ ] HTTP位置修饰符使用合理
- [ ] Fast Pattern选择优化
- [ ] 性能影响评估
- [ ] 测试覆盖充分

## 未来支持计划

### 短期计划 (v0.2.0)
- 支持更多HTTP修饰符 (http.raw_uri, http.stat_msg)
- 基础的正则表达式支持 (pcre)
- 简单的流状态跟踪

### 中期计划 (v0.3.0)
- 完整的pcre支持
- 文件检测基础功能
- 更多的协议支持 (HTTPS解密)

### 长期计划 (v1.0.0)
- 完整的Suricata特性支持
- 高性能文件提取
- 机器学习增强检测

## 故障排除

### 常见问题

#### 1. 规则解析失败
```
错误: Rule parsing error: Unknown option 'pcre'
解决: 移除不支持的选项，使用基础content匹配
```

#### 2. 模式匹配失败
```
错误: Pattern not found in expected HTTP location
解决: 检查HTTP位置修饰符是否正确，验证数据格式
```

#### 3. 性能问题
```
症状: 规则匹配速度慢
原因: Fast Pattern选择不当或规则过于复杂
解决: 优化Fast Pattern，简化规则逻辑
```

### 调试方法
```bash
# 启用详细日志
RUST_LOG=debug ./web_scan_engine --rules rules.rules

# 测试单个规则
./test_rule --rule "content:'admin'; http.uri;" --payload "GET /admin HTTP/1.1"

# 性能分析
perf record ./web_scan_engine --rules large_ruleset.rules
perf report
```

## 总结

Web Scan Rust引擎专注于Web安全检测的高性能实现，当前版本支持Suricata基础规则语法和HTTP协议检测。虽然不支持所有高级特性，但在Web安全检测领域提供了优化的性能和准确的检测能力。

通过合理使用支持的特性和遵循最佳实践，可以构建高效准确的Web安全检测规则集。