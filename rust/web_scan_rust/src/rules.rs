//! 规则管理和解析模块
//!
//! 负责加载、解析和管理Web扫描检测规则。
//! 支持Suricata格式的规则文件，提供高效的规则匹配功能。
//! 支持PCRE（Perl Compatible Regular Expressions）字段。

// 导入错误处理类型
use crate::error::{Result, WebScanError};
// 导入正则表达式库，用于复杂的模式匹配
use regex::{Regex, escape as regex_escape};
// 导入序列化/反序列化trait，用于配置文件处理
use serde::Deserialize;
// 导入HashMap，用于快速查找规则
use std::collections::HashMap;
// 导入文件系统操作
use std::fs;
// 导入路径处理
use std::path::Path;
// 导入PCRE处理模块
use crate::pcre::{PcreProcessor, PcrePattern, PcreMatchType};
// 导入Hyperscan数据库类型
use crate::hyperscan::HyperscanDatabase;

/// 规则动作枚举
/// 
/// 定义当规则匹配时应该执行的动作类型。
/// 这些动作决定了检测到威胁时系统的响应方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]  // C兼容的内存布局
pub enum RuleAction {
    None = 0,   // 无动作（通常用于测试）
    Alert = 1,  // 仅告警，不阻断流量
    Drop = 2,   // 丢弃数据包
    Reset = 3,  // 发送TCP重置包
}

/// HTTP匹配位置枚举
/// 
/// 定义规则应该在HTTP请求/响应的哪个部分进行匹配。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMatchLocation {
    Any,              // 任意位置（默认）
    Method,            // HTTP方法（GET, POST等）
    Uri,               // URI（已解码）
    UriRaw,            // URI（原始，未解码）
    Cookie,            // HTTP Cookie
    RequestBody,       // HTTP请求体
    RequestHeader,     // HTTP请求头
}

/// 带位置的模式结构
///
/// 用于表示一个模式及其对应的HTTP匹配位置和修饰符。
#[derive(Debug, Clone)]
pub struct PatternWithLocation {
    pub pattern: String,
    pub http_location: HttpMatchLocation,
    pub is_fast_pattern: bool,        // 新增：标识是否为fast pattern
    pub nocase: bool,                 // 新增：不区分大小写
    pub startswith: bool,
    pub endswith: bool,
    pub distance: Option<u32>,
    pub depth: Option<u32>,
    pub offset: Option<u32>,
    pub within: Option<u32>,
    pub hyperscan_flags: u32,         // 新增：Hyperscan编译标志
    pub requires_fallback: bool,      // 新增：是否需要regex fallback
    pub header_lowercase: bool,       // 新增：是否对HTTP头部进行小写转换
    pub base64_decode: Option<(u32, bool)>, // 新增：base64解码 (offset, relative)
    pub base64_data: bool,            // 新增：是否在base64解码数据中匹配
}

/// 三层匹配器
///
/// 管理三个匹配层级的数据库和元数据
#[derive(Debug)]
pub struct ThreeLayerMatcher {
    pub fast_pattern_db: Option<HyperscanDatabase>,        // 第一层：fast pattern
    pub full_content_db: Option<HyperscanDatabase>,       // 第二层：完整content
    pub regex_fallback_rules: std::collections::HashMap<u32, Vec<PcrePattern>>, // 第三层：regex fallback
    pub rule_metadata: std::collections::HashMap<u32, RuleMetadata>,        // 规则元数据
}

/// 规则元数据
#[derive(Debug, Clone)]
pub struct RuleMetadata {
    pub has_fast_pattern: bool,
    pub fast_pattern_in_header: bool,
    pub has_pcre_fallback: bool,
    pub total_patterns: usize,
}

/// 修饰符到Hyperscan标志的转换
pub fn modifiers_to_hyperscan_flags(
    nocase: bool,
    startswith: bool,
    _endswith: bool,
) -> u32 {
    let mut flags = 0u32;

    // Hyperscan标志常量定义
    const HS_FLAG_CASELESS: u32 = 0x1;
    const HS_FLAG_SOM_LEFTMOST: u32 = 0x2;

    if nocase {
        flags |= HS_FLAG_CASELESS;
    }
    if startswith {
        flags |= HS_FLAG_SOM_LEFTMOST;
    }

    // endswith需要特殊处理，通过模式调整实现
    flags
}

/// 应用修饰符到模式
pub fn apply_modifier_pattern(
    pattern: &str,
    startswith: bool,
    endswith: bool,
    offset: Option<u32>,
    _depth: Option<u32>,
) -> (String, u32) {
    let mut processed_pattern = pattern.to_string();
    let flags = 0;

    // 处理startswith/endswith
    if startswith && !processed_pattern.starts_with('^') {
        processed_pattern = format!("^{}", processed_pattern);
    }
    if endswith && !processed_pattern.ends_with('$') {
        processed_pattern = format!("{}$", processed_pattern);
    }

    // 处理offset/depth - 转换为Hyperscan语法
    if let Some(offset_val) = offset {
        processed_pattern = format!("^.{{{}}}{}", offset_val, processed_pattern);
    }

    (processed_pattern, flags)
}

/// HTTP解析后的各部分内容
///
/// 用于存储从HTTP请求/响应中提取的各个部分。
#[derive(Debug, Clone)]
pub struct HttpParts {
    pub full_content: &'static str,    // 完整内容
    pub method: &'static str,           // HTTP方法
    pub uri: &'static str,              // URI（已解码）
    pub uri_raw: &'static str,          // URI（原始，未解码）
    pub cookie: &'static str,           // Cookie
    pub request_body: &'static str,      // 请求体
    pub request_header: &'static str,   // 请求头
    // 各部分在原始payload中的字节位置范围（用于验证Hyperscan匹配位置）
    pub method_range: Option<(usize, usize)>,      // (start, end)
    pub uri_range: Option<(usize, usize)>,        // (start, end)
    pub uri_raw_range: Option<(usize, usize)>,    // (start, end)
    pub cookie_range: Option<(usize, usize)>,     // (start, end)
    pub request_body_range: Option<(usize, usize)>, // (start, end)
    pub request_header_range: Option<(usize, usize)>, // (start, end)
}

impl HttpParts {
    /// 从HTTP payload解析各部分
    /// 
    /// # 参数
    /// * `payload` - HTTP payload字节数组
    /// 
    /// # 返回值
    /// * `Result<HttpParts>` - 解析后的HTTP各部分
    pub fn parse(payload: &[u8]) -> Result<Self> {
        // 将payload转换为字符串
        let content = std::str::from_utf8(payload)
            .map_err(|_| WebScanError::RuleParsing("Invalid UTF-8 in HTTP payload".to_string()))?;
        
        // 使用Box::leak创建静态生命周期引用（在检测场景中是安全的）
        let full_content = Box::leak(content.to_string().into_boxed_str());
        
        // 解析HTTP请求行并获取位置信息
        let (method, uri_raw, method_range, uri_raw_range) = Self::parse_request_line_with_positions(content);
        let method = Box::leak(method.to_string().into_boxed_str());
        let uri_raw = Box::leak(uri_raw.to_string().into_boxed_str());
        
        // 解码URI（注意：解码后的URI位置可能与原始URI不同，这里使用原始URI的位置）
        let uri = Self::url_decode(uri_raw);
        let uri = Box::leak(uri.into_boxed_str());
        let uri_range = uri_raw_range; // 使用原始URI的位置
        
        // 解析请求头并获取位置信息
        let (request_header, request_header_range) = Self::extract_request_header_with_position(content);
        let request_header = Box::leak(request_header.into_boxed_str());
        
        // 提取Cookie并获取位置信息
        let (cookie, cookie_range) = Self::extract_cookie_with_position(content);
        let cookie = Box::leak(cookie.into_boxed_str());
        
        // 提取请求体并获取位置信息
        let (request_body, request_body_range) = Self::extract_request_body_with_position(content);
        let request_body = Box::leak(request_body.into_boxed_str());
        
        Ok(HttpParts {
            full_content,
            method,
            uri,
            uri_raw,
            cookie,
            request_body,
            request_header,
            method_range,
            uri_range,
            uri_raw_range,
            cookie_range,
            request_body_range,
            request_header_range,
        })
    }
    
    /// 检查匹配位置是否在指定的HTTP部分范围内
    /// 
    /// # 参数
    /// * `match_from` - 匹配起始位置（字节偏移）
    /// * `match_to` - 匹配结束位置（字节偏移）
    /// * `location` - HTTP匹配位置
    /// * `startswith` - 是否要求匹配在HTTP部分的开始
    /// * `endswith` - 是否要求匹配在HTTP部分的结尾
    /// 
    /// # 返回值
    /// * `bool` - 如果匹配位置在指定范围内返回true
    pub fn is_match_in_location(&self, match_from: u64, match_to: u64, location: HttpMatchLocation, startswith: bool, endswith: bool) -> bool {
        let range = match location {
            HttpMatchLocation::Any => {
                // 对于Any位置，如果使用了startswith/endswith，需要验证是否在payload的开始/结尾
                if startswith {
                    return match_from == 0;
                }
                if endswith {
                    // 需要知道payload的总长度，这里我们使用full_content的长度
                    let payload_end = self.full_content.len() as u64;
                    return match_to == payload_end;
                }
                return true; // 任意位置都匹配
            }
            HttpMatchLocation::Method => self.method_range,
            HttpMatchLocation::Uri => self.uri_range,
            HttpMatchLocation::UriRaw => self.uri_raw_range,
            HttpMatchLocation::Cookie => self.cookie_range,
            HttpMatchLocation::RequestBody => self.request_body_range,
            HttpMatchLocation::RequestHeader => self.request_header_range,
        };
        
        if let Some((start, end)) = range {
            // 检查匹配位置是否完全在指定范围内
            let match_start = match_from as usize;
            let match_end = match_to as usize;
            
            log::debug!("Location verification: location={:?}, range={:?}, match={}..{}, startswith={}, endswith={}", 
                location, range, match_start, match_end, startswith, endswith);
            
            // 检查匹配位置是否与HTTP部分有重叠（匹配位置可能包含HTTP部分，或HTTP部分可能包含匹配位置）
            // 我们要求匹配位置至少部分在HTTP部分范围内
            if match_end <= start || match_start >= end {
                log::debug!("Match outside range: match {}..{} not overlapping with {}..{}", match_start, match_end, start, end);
                return false; // 不在范围内，没有重叠
            }

            // 改进的位置验证：要求匹配位置与HTTP部分有重叠，并且重叠部分至少包含pattern的核心内容
            // 对于多pattern规则，我们更宽松一些，只要匹配位置与HTTP部分有重叠即可
            
            // 如果要求startswith，匹配必须在HTTP部分的开始
            // 注意：Hyperscan可能匹配包含pattern的更长字符串，所以我们需要检查匹配是否从HTTP部分开始
            if startswith {
                // 匹配的开始位置应该在HTTP部分的开始位置（允许一些容差，因为Hyperscan可能匹配了包含pattern的更长字符串）
                if match_start > start {
                    log::debug!("startswith check failed: match_start {} > start {}", match_start, start);
                    return false;
                }
                // 同时，匹配应该包含HTTP部分的开始位置
                if match_end <= start {
                    log::debug!("startswith check failed: match_end {} <= start {}", match_end, start);
                    return false;
                }
            }
            
            // 如果要求endswith，匹配必须在HTTP部分的结尾
            // 注意：Hyperscan可能匹配包含pattern的更长字符串，所以我们需要检查匹配是否到HTTP部分结束
            if endswith {
                // 匹配的结束位置应该在HTTP部分的结束位置（允许一些容差，因为Hyperscan可能匹配了包含pattern的更长字符串）
                if match_end < end {
                    log::debug!("endswith check failed: match_end {} < end {}", match_end, end);
                    return false;
                }
                // 同时，匹配应该包含HTTP部分的结束位置
                if match_start >= end {
                    log::debug!("endswith check failed: match_start {} >= end {}", match_start, end);
                    return false;
                }
            }
            
            log::debug!("Location verification passed");
            true
        } else {
            // 如果没有位置信息，返回false（保守策略）
            log::debug!("No range information available");
            false
        }
    }
    
    /// 解析HTTP请求行
    #[allow(dead_code)]
    fn parse_request_line(content: &str) -> (String, String) {
        if let Some(first_line) = content.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let method = parts[0].to_string();
                let uri = parts[1].to_string();
                return (method, uri);
            }
        }
        (String::new(), String::new())
    }
    
    /// 解析HTTP请求行并返回位置信息
    fn parse_request_line_with_positions(content: &str) -> (String, String, Option<(usize, usize)>, Option<(usize, usize)>) {
        if let Some(first_line) = content.lines().next() {
            // 计算第一行在content中的起始位置
            let first_line_start = first_line.as_ptr() as usize - content.as_ptr() as usize;
            
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let method = parts[0].to_string();
                let uri = parts[1].to_string();
                
                // 计算method的位置（相对于content的起始位置）
                let method_start = first_line_start + (parts[0].as_ptr() as usize - first_line.as_ptr() as usize);
                let method_end = method_start + parts[0].len();
                
                // 计算URI的位置（相对于content的起始位置）
                let uri_start = first_line_start + (parts[1].as_ptr() as usize - first_line.as_ptr() as usize);
                let uri_end = uri_start + parts[1].len();
                
                return (method, uri, Some((method_start, method_end)), Some((uri_start, uri_end)));
            }
        }
        (String::new(), String::new(), None, None)
    }
    
    /// URL解码
    fn url_decode(encoded: &str) -> String {
        // 简单的URL解码实现
        let mut decoded = String::new();
        let mut chars = encoded.chars().peekable();
        
        while let Some(ch) = chars.next() {
            if ch == '%' {
                let mut hex = String::new();
                if let Some(c1) = chars.next() {
                    hex.push(c1);
                    if let Some(c2) = chars.next() {
                        hex.push(c2);
                        if let Ok(byte_val) = u8::from_str_radix(&hex, 16) {
                            decoded.push(byte_val as char);
                            continue;
                        }
                    }
                }
                decoded.push('%');
                decoded.push_str(&hex);
            } else if ch == '+' {
                decoded.push(' ');
            } else {
                decoded.push(ch);
            }
        }
        
        decoded
    }
    
    /// 提取请求头部分
    #[allow(dead_code)]
    fn extract_request_header(content: &str) -> String {
        if let Some(body_start) = content.find("\r\n\r\n") {
            content[..body_start].to_string()
        } else if let Some(body_start) = content.find("\n\n") {
            content[..body_start].to_string()
        } else {
            content.to_string()
        }
    }
    
    /// 提取请求头部分并返回位置信息
    fn extract_request_header_with_position(content: &str) -> (String, Option<(usize, usize)>) {
        if let Some(body_start) = content.find("\r\n\r\n") {
            let header = content[..body_start].to_string();
            let range = Some((0, body_start));
            (header, range)
        } else if let Some(body_start) = content.find("\n\n") {
            let header = content[..body_start].to_string();
            let range = Some((0, body_start));
            (header, range)
        } else {
            let header = content.to_string();
            let range = Some((0, content.len()));
            (header, range)
        }
    }
    
    /// 提取Cookie
    #[allow(dead_code)]
    fn extract_cookie(content: &str) -> String {
        // 查找Cookie头
        for line in content.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("cookie:") {
                return line[7..].trim().to_string();
            }
        }
        String::new()
    }
    
    /// 提取Cookie并返回位置信息
    fn extract_cookie_with_position(content: &str) -> (String, Option<(usize, usize)>) {
        // 查找Cookie头
        for line in content.lines() {
            let line_lower = line.to_lowercase();
            if line_lower.starts_with("cookie:") {
                let cookie_value = line[7..].trim();
                if !cookie_value.is_empty() {
                    // 计算cookie值在content中的位置
                    // 首先找到这一行在content中的起始位置
                    let line_start = line.as_ptr() as usize - content.as_ptr() as usize;
                    // 然后找到cookie值在这一行中的位置
                    let cookie_value_start_in_line = line.find(cookie_value).unwrap_or(7);
                    let cookie_start = line_start + cookie_value_start_in_line;
                    let cookie_end = cookie_start + cookie_value.len();
                    return (cookie_value.to_string(), Some((cookie_start, cookie_end)));
                }
            }
        }
        (String::new(), None)
    }
    
    /// 提取请求体
    #[allow(dead_code)]
    fn extract_request_body(content: &str) -> String {
        if let Some(body_start) = content.find("\r\n\r\n") {
            content[body_start + 4..].to_string()
        } else if let Some(body_start) = content.find("\n\n") {
            content[body_start + 2..].to_string()
        } else {
            String::new()
        }
    }
    
    /// 提取请求体并返回位置信息
    fn extract_request_body_with_position(content: &str) -> (String, Option<(usize, usize)>) {
        if let Some(body_start) = content.find("\r\n\r\n") {
            let body = content[body_start + 4..].to_string();
            let body_start_pos = body_start + 4;
            let body_end_pos = content.len();
            (body, Some((body_start_pos, body_end_pos)))
        } else if let Some(body_start) = content.find("\n\n") {
            let body = content[body_start + 2..].to_string();
            let body_start_pos = body_start + 2;
            let body_end_pos = content.len();
            (body, Some((body_start_pos, body_end_pos)))
        } else {
            (String::new(), None)
        }
    }
}

// 为RuleAction实现Default trait
// 默认动作是Alert（告警），这是最安全的选择
impl Default for RuleAction {
    fn default() -> Self {
        RuleAction::Alert
    }
}

/// 数据包流向枚举
///
/// 定义规则应该在哪个方向的数据包上进行匹配。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleFlowDirection {
    Any = 0,       // 任意方向（默认）
    ToServer = 1,  // 客户端到服务器的请求包
    ToClient = 2,  // 服务器到客户端的响应包
}

/// 检测规则结构体
///
/// 表示一个完整的Web扫描检测规则，包含匹配模式、动作和元数据。
/// 支持content模式和PCRE模式，支持双向检测。
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,                                    // 规则唯一标识符
    pub action: RuleAction,                         // 匹配时执行的动作
    pub message: String,                            // 规则描述信息
    pub pattern: String,                            // 原始匹配模式（向后兼容，用于Hyperscan编译）
    pub compiled_regex: Option<Regex>,              // 编译后的正则表达式（可选）
    pub http_location: HttpMatchLocation,           // HTTP匹配位置（向后兼容，用于单pattern规则）
    pub metadata: HashMap<String, String>,          // 额外的元数据
    pub patterns: Vec<PatternWithLocation>,         // 多个模式及其位置（支持多content规则）
    pub fast_pattern_index: Option<usize>,          // Fast pattern索引（用于优化：先匹配fast pattern，命中后再匹配其他pattern）
    pub pcre_patterns: Vec<PcrePattern>,            // PCRE模式列表
    pub flow_direction: RuleFlowDirection,          // 流向要求（新增：支持双向检测）
    pub status_codes: Vec<u16>,                     // 状态码列表（新增：仅对响应包有效）
    pub requires_established: bool,                 // 是否要求已建立连接（新增：flow established状态）
}

impl Rule {
    /// 创建新的规则实例
    /// 
    /// # 参数
    /// * `id` - 规则ID，必须唯一
    /// * `action` - 匹配时的动作
    /// * `message` - 规则描述
    /// * `pattern` - 匹配模式（可以是简单字符串或正则表达式）
    /// 
    /// # 返回值
    /// * `Result<Self>` - 成功时返回Rule实例，失败时返回错误
    pub fn new(id: u32, action: RuleAction, message: String, pattern: String) -> Result<Self> {
        // 尝试编译正则表达式（如果模式不为空）
        // 如果编译失败，将pattern作为字面字符串处理（Suricata规则中的content通常是字面字符串）
        let compiled_regex = if pattern.is_empty() {
            None  // 空模式不需要正则表达式
        } else {
            // 尝试编译正则表达式
            // 如果失败，将其作为字面字符串处理（不报错）
            match Regex::new(&pattern) {
                Ok(regex) => Some(regex),
                Err(_) => {
                    // 正则表达式编译失败，将其作为字面字符串处理
                    // 这在Suricata规则中很常见，因为content选项通常是字面字符串
                    None
                }
            }
        };

        // 创建并返回Rule实例
        Ok(Rule {
            id,
            action,
            message,
            pattern: pattern.clone(),  // 向后兼容
            compiled_regex,
            http_location: HttpMatchLocation::Any,  // 默认匹配任意位置（向后兼容）
            metadata: HashMap::new(),  // 初始化为空的HashMap
            patterns: vec![PatternWithLocation {  // 默认只有一个pattern
                pattern,
                http_location: HttpMatchLocation::Any,
                is_fast_pattern: false,       // 默认不是fast pattern
                nocase: false,                // 默认区分大小写
                startswith: false,
                endswith: false,
                distance: None,
                depth: None,
                offset: None,
                within: None,
                hyperscan_flags: modifiers_to_hyperscan_flags(false, false, false),  // 计算flags
                requires_fallback: false,     // 默认不需要fallback
                header_lowercase: false,      // 默认不进行小写转换
                base64_decode: None,          // 默认不进行base64解码
                base64_data: false,           // 默认不是base64数据匹配
            }],
            fast_pattern_index: Some(0),  // 单pattern规则，fast pattern就是它自己
            pcre_patterns: Vec::new(),  // 初始化为空的PCRE模式列表
            flow_direction: RuleFlowDirection::Any,  // 默认匹配任意方向
            status_codes: Vec::new(),  // 默认不限制状态码
            requires_established: false,  // 默认不要求established连接
        })
    }

    /// 检查此规则是否匹配给定内容
    /// 
    /// # 参数
    /// * `content` - 要检查的内容字符串
    /// 
    /// # 返回值
    /// * `bool` - 如果匹配返回true，否则返回false
    pub fn matches(&self, content: &str) -> bool {
        // 使用模式匹配检查是否有编译的正则表达式
        match &self.compiled_regex {
            // 如果有正则表达式，使用正则匹配
            Some(regex) => regex.is_match(content),
            // 如果没有正则表达式，使用简单的字符串包含检查
            None => content.contains(&self.pattern),
        }
    }

    /// 检查此规则是否匹配HTTP内容
    /// 
    /// 根据规则的http_location，在相应的HTTP部分进行匹配。
    /// 
    /// # 参数
    /// * `http_parts` - HTTP解析后的各部分内容
    /// 
    /// # 返回值
    /// * `bool` - 如果匹配返回true，否则返回false
    pub fn matches_http(&self, http_parts: &HttpParts) -> bool {
        let target_content = match self.http_location {
            HttpMatchLocation::Any => http_parts.full_content,
            HttpMatchLocation::Method => http_parts.method,
            HttpMatchLocation::Uri => http_parts.uri,
            HttpMatchLocation::UriRaw => http_parts.uri_raw,
            HttpMatchLocation::Cookie => http_parts.cookie,
            HttpMatchLocation::RequestBody => http_parts.request_body,
            HttpMatchLocation::RequestHeader => http_parts.request_header,
        };

        if target_content.is_empty() {
            return false;
        }

        // 使用模式匹配检查是否有编译的正则表达式
        match &self.compiled_regex {
            // 如果有正则表达式，使用正则匹配
            Some(regex) => regex.is_match(target_content),
            // 如果没有正则表达式，使用简单的字符串包含检查
            None => target_content.contains(&self.pattern),
        }
    }

    /// 检查规则是否完全匹配（多条件规则）
    ///
    /// 这个方法验证规则的所有pattern是否都在正确的HTTP位置找到。
    /// 对于多content规则，需要所有条件都满足才返回true。
    /// 支持内容处理器，包括小写转换和base64解码。
    ///
    /// # 参数
    /// * `data` - 完整的HTTP数据
    ///
    /// # 返回值
    /// * `bool` - 如果规则完全匹配返回true，否则返回false
    pub fn does_rule_fully_match(&self, data: &str) -> bool {
        // 检查所有pattern是否都在正确的位置找到
        for (pattern_idx, pattern_with_location) in self.patterns.iter().enumerate() {
            let target_content = self.extract_http_part(data, pattern_with_location.http_location);

            log::debug!("Rule {}: checking pattern {} '{}' in {:?} -> extracted: '{}' -> contains: {}",
                     self.id, pattern_idx, pattern_with_location.pattern, pattern_with_location.http_location,
                     target_content, target_content.contains(&pattern_with_location.pattern));

            if target_content.is_empty() {
                log::debug!("Rule {}: pattern {} failed - empty target content", self.id, pattern_idx);
                return false;
            }

            // 应用内容处理器
            let processed_content = match self.apply_content_processors(&pattern_with_location, &target_content) {
                Ok(content) => content,
                Err(e) => {
                    log::debug!("Rule {}: pattern {} content processing failed: {}", self.id, pattern_idx, e);
                    return false;
                }
            };

            // 检查pattern是否在正确的位置找到
            // 对于包含转义十六进制的pattern，需要进行字节级比较
            let pattern_match = if pattern_with_location.pattern.contains("\\x") {
                // 将转义的十六进制字符串转换为实际字节，然后进行字节匹配
                self.pattern_matches_bytes(&pattern_with_location.pattern, &processed_content)
            } else {
                // 普通字符串匹配
                processed_content.contains(&pattern_with_location.pattern)
            };

            if !pattern_match {
                log::debug!("Rule {}: pattern {} failed - '{}' not found in processed content", self.id, pattern_idx, pattern_with_location.pattern);
                return false;
            } else {
                log::debug!("Rule {}: pattern {} passed - '{}' found in processed content", self.id, pattern_idx, pattern_with_location.pattern);
            }
        }

        log::debug!("Rule {}: all patterns matched - fully matches", self.id);
        true
    }

    /// 应用内容处理器到目标内容
    ///
    /// # 参数
    /// * `pattern` - 包含内容处理配置的pattern
    /// * `content` - 要处理的内容
    ///
    /// # 返回值
    /// * `Result<String>` - 处理后的内容或错误
    fn apply_content_processors(&self, pattern: &PatternWithLocation, content: &str) -> crate::error::Result<String> {
        use crate::content_processor::{ChainProcessor, ContentProcessor};

        // 创建内容处理器链
        let processor = ChainProcessor::from_pattern_config(
            pattern.header_lowercase,
            pattern.base64_decode,
            pattern.base64_data,
        );

        // 如果没有处理器，直接返回原内容
        if processor.processors.len() == 0 {
            return Ok(content.to_string());
        }

        // 应用处理器
        processor.process(content).map_err(|e| {
            WebScanError::ContentProcessing(format!("Content processing failed: {}", e))
        })
    }

    /// 检查转义十六进制pattern是否匹配目标内容的字节
    ///
    /// 这个方法将pattern中的转义十六进制序列（如\x28）转换为实际字节，
    /// 然后在目标内容中查找这些字节序列。
    ///
    /// # 参数
    /// * `pattern` - 可能包含转义十六进制序列的pattern字符串
    /// * `target_content` - 目标内容字符串
    ///
    /// # 返回值
    /// * `bool` - 如果pattern字节序列在目标内容中找到返回true
    fn pattern_matches_bytes(&self, pattern: &str, target_content: &str) -> bool {
        let mut pattern_bytes = Vec::new();
        let mut i = 0;
        let bytes = pattern.as_bytes();

        while i < bytes.len() {
            if bytes[i] == b'\\' && i + 1 < bytes.len() && bytes[i + 1] == b'x' {
                // 找到转义十六进制序列 \xXX
                if i + 3 < bytes.len() {
                    let hex_str = std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or("00");
                    if let Ok(byte_val) = u8::from_str_radix(hex_str, 16) {
                        pattern_bytes.push(byte_val);
                    }
                    i += 4;
                } else {
                    i += 1;
                }
            } else {
                // 普通字符
                pattern_bytes.push(bytes[i]);
                i += 1;
            }
        }

        // 在目标内容的字节中查找pattern字节序列
        let target_bytes = target_content.as_bytes();

        // 对于单字节的pattern，使用简单的查找
        if pattern_bytes.len() == 1 {
            return target_bytes.contains(&pattern_bytes[0]);
        }

        // 对于多字节pattern，使用滑动窗口查找
        for window in target_bytes.windows(pattern_bytes.len()) {
            if window == pattern_bytes {
                return true;
            }
        }

        false
    }

    /// 从HTTP数据中提取指定部分
    ///
    /// # 参数
    /// * `data` - 完整的HTTP数据
    /// * `location` - 要提取的HTTP部分
    ///
    /// # 返回值
    /// * `&str` - 提取的HTTP部分
    pub fn extract_http_part<'a>(&self, data: &'a str, location: HttpMatchLocation) -> &'a str {
        match location {
            HttpMatchLocation::Any => data,
            HttpMatchLocation::Method => {
                // 提取HTTP方法（第一行的第一个词）
                if let Some(end) = data.find(' ') {
                    &data[..end]
                } else {
                    ""
                }
            }
            HttpMatchLocation::Uri | HttpMatchLocation::UriRaw => {
                // 提取URI（第一个空格后的内容到第二个空格）
                if let Some(start) = data.find(' ') {
                    let uri_start = start + 1;
                    if let Some(end) = data[uri_start..].find(' ') {
                        &data[uri_start..uri_start + end]
                    } else {
                        ""
                    }
                } else {
                    ""
                }
            }
            HttpMatchLocation::Cookie => {
                // 查找Cookie头部
                if let Some(cookie_start) = data.to_lowercase().find("cookie:") {
                    let start = cookie_start + 7; // 跳过"cookie:"
                    if let Some(end) = data[start..].find("\r\n") {
                        &data[start..start + end].trim()
                    } else {
                        ""
                    }
                } else {
                    ""
                }
            }
            HttpMatchLocation::RequestBody => {
                // 查找HTTP body（在\r\n\r\n之后的内容）
                if let Some(header_end) = data.find("\r\n\r\n") {
                    &data[header_end + 4..]
                } else {
                    ""
                }
            }
            HttpMatchLocation::RequestHeader => {
                // 提取请求头（从第一行到\r\n\r\n）
                if let Some(header_end) = data.find("\r\n\r\n") {
                    &data[..header_end]
                } else {
                    ""
                }
            }
        }
    }

    /// 添加元数据键值对
    /// 
    /// 元数据用于存储规则的额外信息，如分类、优先级等。
    /// 
    /// # 参数
    /// * `key` - 元数据键
    /// * `value` - 元数据值
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// 获取元数据值
    ///
    /// # 参数
    /// * `key` - 要查找的元数据键
    ///
    /// # 返回值
    /// * `Option<&String>` - 如果找到返回Some(值)，否则返回None
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// 添加PCRE模式
    ///
    /// # 参数
    /// * `pcre_pattern` - PCRE模式
    pub fn add_pcre_pattern(&mut self, pcre_pattern: PcrePattern) {
        self.pcre_patterns.push(pcre_pattern);
    }

    /// 检查规则是否有PCRE模式
    ///
    /// # 返回值
    /// * `bool` - 如果有PCRE模式返回true
    pub fn has_pcre_patterns(&self) -> bool {
        !self.pcre_patterns.is_empty()
    }

    /// 检查PCRE模式是否匹配内容
    ///
    /// # 参数
    /// * `content` - 要检查的内容
    ///
    /// # 返回值
    /// * `bool` - 如果有任何PCRE模式匹配返回true
    pub fn pcre_matches(&self, content: &str) -> bool {
        for pcre_pattern in &self.pcre_patterns {
            match pcre_pattern.match_type {
                PcreMatchType::RegexFallback => {
                    if let Some(regex) = &pcre_pattern.compiled_regex {
                        if regex.is_match(content) {
                            log::debug!("PCRE fallback pattern '{}' matched for rule {}", pcre_pattern.raw_pattern, self.id);
                            return true;
                        }
                    }
                }
                // Hyperscan和ConvertedHyperscan在规则解析阶段已经处理
                // 这里只处理fallback情况
                _ => {
                    log::debug!("PCRE pattern '{}' (type: {:?}) should be handled by Hyperscan for rule {}",
                              pcre_pattern.raw_pattern, pcre_pattern.match_type, self.id);
                }
            }
        }
        false
    }

    /// 检查PCRE模式是否匹配HTTP内容的特定部分
    ///
    /// # 参数
    /// * `http_parts` - HTTP解析后的各部分内容
    ///
    /// # 返回值
    /// * `bool` - 如果有任何PCRE模式在指定位置匹配返回true
    pub fn pcre_matches_http(&self, http_parts: &HttpParts) -> bool {
        for pcre_pattern in &self.pcre_patterns {
            // 根据PCRE模式的位置选择目标内容
            let target_content = match pcre_pattern.http_location {
                HttpMatchLocation::Any => http_parts.full_content,
                HttpMatchLocation::Method => http_parts.method,
                HttpMatchLocation::Uri => http_parts.uri,
                HttpMatchLocation::UriRaw => http_parts.uri_raw,
                HttpMatchLocation::Cookie => http_parts.cookie,
                HttpMatchLocation::RequestBody => http_parts.request_body,
                HttpMatchLocation::RequestHeader => http_parts.request_header,
            };

            if target_content.is_empty() {
                continue;
            }

            match pcre_pattern.match_type {
                PcreMatchType::RegexFallback => {
                    if let Some(regex) = &pcre_pattern.compiled_regex {
                        if regex.is_match(target_content) {
                            log::debug!("PCRE fallback pattern '{}' matched in {:?} for rule {}",
                                      pcre_pattern.raw_pattern, pcre_pattern.http_location, self.id);
                            return true;
                        }
                    }
                }
                // Hyperscan和ConvertedHyperscan在规则解析阶段已经处理
                _ => {
                    log::debug!("PCRE pattern '{}' (type: {:?}) should be handled by Hyperscan for rule {}",
                              pcre_pattern.raw_pattern, pcre_pattern.match_type, self.id);
                }
            }
        }
        false
    }

    /// 获取所有用于Hyperscan编译的模式
    ///
    /// 返回所有content pattern和兼容Hyperscan的PCRE pattern
    ///
    /// # 返回值
    /// * `Vec<(String, u32)>` - 模式字符串和规则ID的元组列表
    /// 将content模式转义为Hyperscan字面量模式
    ///
    /// Hyperscan将所有输入视为正则表达式，所以content模式中的特殊字符需要转义
    pub fn escape_for_hyperscan_literal(pattern: &str) -> String {
        // Hyperscan支持字面量模式，但需要转义特殊字符
        // 由于我们已经将十六进制内容转换为\xXX格式，这里主要是转义正则特殊字符

        // 如果已经是转义格式（包含\x），直接返回
        if pattern.contains("\\x") {
            return pattern.to_string();
        }

        // 对于普通字符串，转义正则特殊字符
        let mut escaped = String::new();
        for ch in pattern.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '.' => escaped.push_str("\\."),
                '^' => escaped.push_str("\\^"),
                '$' => escaped.push_str("\\$"),
                '*' => escaped.push_str("\\*"),
                '+' => escaped.push_str("\\+"),
                '?' => escaped.push_str("\\?"),
                '(' => escaped.push_str("\\("),
                ')' => escaped.push_str("\\)"),
                '[' => escaped.push_str("\\["),
                ']' => escaped.push_str("\\]"),
                '{' => escaped.push_str("\\{"),
                '}' => escaped.push_str("\\}"),
                '|' => escaped.push_str("\\|"),
                _ => escaped.push(ch),
            }
        }
        escaped
    }

    pub fn get_hyperscan_patterns(&self) -> Vec<(String, u32)> {
        let mut patterns = Vec::new();

        // 添加content patterns（作为字面量字符串处理）
        for pattern_with_loc in &self.patterns {
            // 将content模式转换为Hyperscan兼容的字面量模式
            let original_pattern = &pattern_with_loc.pattern;
            let literal_pattern = Self::escape_for_hyperscan_literal(original_pattern);

            // 调试输出：检查转义是否生效
            if original_pattern.starts_with('?') || original_pattern.starts_with('+') || original_pattern.starts_with('*') {
                log::debug!("转义模式: '{}' -> '{}'", original_pattern, literal_pattern);
            }

            patterns.push((literal_pattern, self.id));
        }

        // 添加兼容Hyperscan的PCRE patterns
        for pcre_pattern in &self.pcre_patterns {
            match pcre_pattern.match_type {
                PcreMatchType::Hyperscan | PcreMatchType::ConvertedHyperscan => {
                    patterns.push((pcre_pattern.processed_pattern.clone(), self.id));
                }
                PcreMatchType::RegexFallback => {
                    // Fallback模式不添加到Hyperscan编译
                    log::debug!("Skipping fallback PCRE pattern '{}' for Hyperscan compilation",
                              pcre_pattern.raw_pattern);
                }
            }
        }

        patterns
    }

    /// 检查规则是否需要fallback处理
    ///
    /// # 返回值
    /// * `bool` - 如果有任何PCRE模式需要fallback处理返回true
    pub fn needs_fallback_processing(&self) -> bool {
        self.pcre_patterns.iter().any(|p| p.match_type == PcreMatchType::RegexFallback)
    }

    /// 检查规则是否匹配指定的数据包流向
    ///
    /// # 参数
    /// * `packet_direction` - 数据包流向（请求/响应）
    ///
    /// # 返回值
    /// * `bool` - 如果流向匹配返回true
    pub fn matches_flow_direction(&self, packet_direction: crate::protocol::PacketDirection) -> bool {
        use crate::protocol::PacketDirection;

        match self.flow_direction {
            RuleFlowDirection::Any => true,
            RuleFlowDirection::ToServer => packet_direction == PacketDirection::ToServer,
            RuleFlowDirection::ToClient => packet_direction == PacketDirection::ToClient,
        }
    }

    /// 检查规则是否匹配指定的HTTP状态码
    ///
    /// # 参数
    /// * `status_code` - HTTP状态码（可选）
    ///
    /// # 返回值
    /// * `bool` - 如果状态码匹配或规则不限制状态码返回true
    pub fn matches_status_code(&self, status_code: Option<u16>) -> bool {
        // 如果规则不限制状态码，则匹配
        if self.status_codes.is_empty() {
            return true;
        }

        // 如果没有提供状态码，则不匹配
        if let Some(code) = status_code {
            self.status_codes.contains(&code)
        } else {
            false
        }
    }

    /// 检查规则是否满足连接状态要求
    ///
    /// # 参数
    /// * `is_established` - 连接是否已建立
    ///
    /// # 返回值
    /// * `bool` - 如果满足要求返回true
    pub fn matches_established_state(&self, is_established: bool) -> bool {
        !self.requires_established || is_established
    }

    /// 综合检查规则是否匹配数据包的流向和状态信息
    ///
    /// # 参数
    /// * `packet_direction` - 数据包流向
    /// * `status_code` - HTTP状态码（可选）
    /// * `is_established` - 连接是否已建立
    ///
    /// # 返回值
    /// * `bool` - 如果所有条件都满足返回true
    pub fn matches_packet_metadata(&self, packet_direction: crate::protocol::PacketDirection,
                                 status_code: Option<u16>, is_established: bool) -> bool {
        self.matches_flow_direction(packet_direction) &&
        self.matches_status_code(status_code) &&
        self.matches_established_state(is_established)
    }
}

/// 规则管理器结构体
///
/// 负责管理所有检测规则，包括加载、存储、查找和匹配规则。
/// 使用HashMap提供O(1)时间复杂度的规则查找。
pub struct RuleManager {
    rules: HashMap<u32, Rule>,           // 规则存储：ID -> Rule
    rule_count: u32,                     // 当前规则总数
    enabled: bool,                       // 是否启用规则管理
    pcre_processor: PcreProcessor,       // PCRE处理器
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleManager {
    /// 创建新的规则管理器实例
    ///
    /// 初始化空的规则集合和默认配置。
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),        // 创建空的HashMap
            rule_count: 0,                // 初始规则数量为0
            enabled: true,                // 默认启用
            pcre_processor: PcreProcessor::new(),  // 创建PCRE处理器
        }
    }

    /// 添加新规则
    /// 
    /// # 参数
    /// * `rule` - 要添加的规则实例
    /// 
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        // 检查规则ID是否已存在
        if self.rules.contains_key(&rule.id) {
            return Err(WebScanError::RuleParsing(
                format!("Rule with ID {} already exists", rule.id)
            ));
        }

        // 将规则添加到HashMap中
        self.rules.insert(rule.id, rule);
        self.rule_count += 1;            // 增加规则计数
        
        Ok(())
    }

    /// 根据ID查找规则
    /// 
    /// # 参数
    /// * `id` - 要查找的规则ID
    /// 
    /// # 返回值
    /// * `Option<&Rule>` - 如果找到返回Some(规则引用)，否则返回None
    pub fn get_rule(&self, id: u32) -> Option<&Rule> {
        self.rules.get(&id)
    }

    /// 移除指定ID的规则
    /// 
    /// # 参数
    /// * `id` - 要移除的规则ID
    /// 
    /// # 返回值
    /// * `bool` - 如果成功移除返回true，如果规则不存在返回false
    pub fn remove_rule(&mut self, id: u32) -> bool {
        // remove()方法返回Option<Rule>，如果存在则返回Some(规则)，否则返回None
        if let Some(_) = self.rules.remove(&id) {
            self.rule_count -= 1;        // 减少规则计数
            true
        } else {
            false
        }
    }

    /// 获取所有规则
    /// 
    /// # 返回值
    /// * `&HashMap<u32, Rule>` - 所有规则的引用
    pub fn get_all_rules(&self) -> &HashMap<u32, Rule> {
        &self.rules
    }

    /// 获取规则总数
    /// 
    /// # 返回值
    /// * `u32` - 当前规则总数
    pub fn rule_count(&self) -> u32 {
        self.rule_count
    }

    /// 检查内容是否匹配任何规则
    /// 
    /// 这是规则管理的核心功能，遍历所有规则检查是否有匹配。
    /// 
    /// # 参数
    /// * `content` - 要检查的内容
    /// 
    /// # 返回值
    /// * `Option<&Rule>` - 如果匹配到规则返回Some(规则引用)，否则返回None
    pub fn match_content(&self, content: &str) -> Option<&Rule> {
        // 如果规则管理未启用，直接返回None
        if !self.enabled {
            return None;
        }

        // 遍历所有规则，找到第一个匹配的
        // iter()创建迭代器，find()找到第一个满足条件的元素
        self.rules.values().find(|rule| rule.matches(content))
    }

    /// 检查HTTP内容是否匹配任何规则
    /// 
    /// 根据规则的http_location在相应的HTTP部分进行匹配。
    /// 
    /// # 参数
    /// * `http_parts` - HTTP解析后的各部分内容
    /// 
    /// # 返回值
    /// * `Option<&Rule>` - 如果匹配到规则返回Some(规则引用)，否则返回None
    pub fn match_http_content(&self, http_parts: &HttpParts) -> Option<&Rule> {
        // 如果规则管理未启用，直接返回None
        if !self.enabled {
            return None;
        }

        // 遍历所有规则，找到第一个匹配的
        self.rules.values().find(|rule| rule.matches_http(http_parts))
    }

    /// 从文件加载规则
    ///
    /// 支持多种格式的规则文件，如JSON、TOML、Hyperscan等。
    ///
    /// # 参数
    /// * `path` - 规则文件路径
    ///
    /// # 返回值
    /// * `Result<u32>` - 成功返回加载的规则数量，失败返回错误
    pub fn load_rules_from_file(&mut self, path: &Path) -> Result<u32> {
        // 读取文件内容
        let content = fs::read_to_string(path)?;
        
        // 根据文件扩展名选择解析方法
        let loaded_count = match path.extension().and_then(|s| s.to_str()) {
            Some("json") => self.parse_json_rules(&content)?,
            Some("toml") => self.parse_toml_rules(&content)?,
            Some("rules") => self.parse_hyperscan_rules(&content)?,
            Some("hs") => self.parse_hyperscan_rules(&content)?,
            _ => return Err(WebScanError::RuleParsing(
                "Unsupported file format. Only JSON, TOML, and Hyperscan (.rules/.hs) are supported.".to_string()
            )),
        };

        Ok(loaded_count)
    }

    /// 解析Hyperscan格式的规则
    ///
    /// 支持Suricata/Snort风格的规则格式，包括多行规则。
    ///
    /// # 参数
    /// * `content` - Hyperscan格式的规则内容
    ///
    /// # 返回值
    /// * `Result<u32>` - 成功返回解析的规则数量，失败返回错误
    fn parse_hyperscan_rules(&mut self, content: &str) -> Result<u32> {
        let mut loaded_count = 0;
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;
        
        while i < lines.len() {
            let line = lines[i].trim();
            
            // 跳过空行和注释行
            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }
            
            // 检查是否是规则开始（action protocol ...）
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                i += 1;
                continue;
            }
            
            // 只处理HTTP规则
            let action_str = parts[0];
            let protocol = parts[1];
            
            if !matches!(action_str, "alert" | "drop" | "reset" | "pass") || protocol != "http" {
                // 不是HTTP规则，跳过
                i += 1;
                continue;
            }
            
            // 尝试合并多行规则
            let mut rule_text = line.to_string();
            let start_line_num = i + 1;
            let mut paren_depth = 0;
            let mut in_string = false;
            let mut escape_next = false;
            
            // 计算当前行的括号深度
            for ch in line.chars() {
                if escape_next {
                    escape_next = false;
                    continue;
                }
                match ch {
                    '\\' => escape_next = true,
                    '"' => in_string = !in_string,
                    '(' if !in_string => paren_depth += 1,
                    ')' if !in_string => {
                        paren_depth -= 1;
                        if paren_depth < 0 {
                            break; // 多余的右括号，可能是错误
                        }
                    }
                    _ => {}
                }
            }
            
            // 如果括号未匹配，继续读取后续行
            i += 1;
            while paren_depth > 0 && i < lines.len() {
                let next_line = lines[i].trim();
                
                // 跳过空行和注释行（但在规则中间不应该有注释）
                if next_line.is_empty() {
                    rule_text.push(' '); // 保留空格
                    i += 1;
                    continue;
                }
                
                if next_line.starts_with('#') {
                    // 规则中间的注释，跳过
                    i += 1;
                    continue;
                }
                
                // 追加到规则文本
                rule_text.push(' ');
                rule_text.push_str(next_line);
                
                // 更新括号深度
                for ch in next_line.chars() {
                    if escape_next {
                        escape_next = false;
                        continue;
                    }
                    match ch {
                        '\\' => escape_next = true,
                        '"' => in_string = !in_string,
                        '(' if !in_string => paren_depth += 1,
                        ')' if !in_string => {
                            paren_depth -= 1;
                            if paren_depth == 0 {
                                break; // 找到匹配的右括号
                            }
                        }
                        _ => {}
                    }
                }
                
                i += 1;
            }
            
            // 如果括号仍未匹配，记录警告但继续
            if paren_depth != 0 {
                log::warn!("Unmatched parentheses in rule starting at line {}", start_line_num);
                continue;
            }
            
            // 解析合并后的规则
            match self.parse_suricata_rule(&rule_text, start_line_num) {
                Ok(rule) => {
                    // 如果添加规则失败（比如ID冲突），记录警告但继续处理其他规则
                    match self.add_rule(rule) {
                        Ok(_) => {
                            loaded_count += 1;
                        }
                        Err(e) => {
                            // 记录添加失败，但不中断整个加载过程
                            log::warn!("Failed to add rule at line {}: {}", start_line_num, e);
                        }
                    }
                }
                Err(e) => {
                    // 记录解析失败，但不中断整个加载过程
                    log::warn!("Failed to parse rule at line {}: {}", start_line_num, e);
                }
            }
        }
        
        Ok(loaded_count)
    }

    /// 解析单个Suricata/Snort规则
    ///
    /// # 参数
    /// * `rule_line` - 规则行内容
    /// * `line_num` - 行号（用于错误报告）
    ///
    /// # 返回值
    /// * `Result<Rule>` - 解析后的规则
    pub fn parse_suricata_rule(&mut self, rule_line: &str, line_num: usize) -> Result<Rule> {
        // 简单的规则解析，支持基本的Suricata格式
        // 示例: alert http any any -> any any (msg:"Admin access"; content:"/admin/"; sid:1001;)
        
        // 提取动作部分
        let parts: Vec<&str> = rule_line.split_whitespace().collect();
        if parts.len() < 7 {
            return Err(WebScanError::RuleParsing(
                format!("Invalid rule format at line {}: insufficient parts", line_num)
            ));
        }
        
        let action_str = parts[0];
        let action = match action_str {
            "alert" => RuleAction::Alert,
            "drop" => RuleAction::Drop,
            "reset" => RuleAction::Reset,
            "pass" | "none" => RuleAction::None,
            _ => return Err(WebScanError::RuleParsing(
                format!("Invalid action '{}' at line {}", action_str, line_num)
            )),
        };
        
        // 检查是否为HTTP规则
        // 如果不是HTTP规则（如TCP），跳过该规则（不报错，因为规则文件中可能包含多种协议）
        log::debug!("Processing rule: {}", rule_line);
        if parts[1] != "http" {
            return Err(WebScanError::RuleParsing(
                format!("Skipping non-HTTP rule (protocol: {}) at line {}", parts[1], line_num)
            ));
        }
        
        // 提取选项部分
        let options_start = rule_line.find('(');
        let options_end = rule_line.rfind(')');
        
        if options_start.is_none() || options_end.is_none() || options_end.unwrap() <= options_start.unwrap() {
            return Err(WebScanError::RuleParsing(
                format!("Invalid options format at line {}", line_num)
            ));
        }
        
        let options_str = &rule_line[options_start.unwrap() + 1..options_end.unwrap()];
        
        // 解析选项
        let mut message = "Unknown rule".to_string();
        let mut sid = 0u32;
        
        // 用于收集多个pattern及其位置信息
        let mut patterns: Vec<PatternWithLocation> = Vec::new();

        // 用于收集PCRE模式
        let mut pcre_patterns: Vec<PcrePattern> = Vec::new();

        // 当前正在解析的pattern的状态
        let mut current_pattern = String::new();
        let mut current_http_location = HttpMatchLocation::Any;
        let mut current_nocase = false;          // 新增：nocase修饰符状态
        let mut current_startswith = false;
        let mut current_endswith = false;
        let mut current_distance: Option<u32> = None;
        let mut current_depth: Option<u32> = None;
        let mut current_offset: Option<u32> = None;
        let mut current_within: Option<u32> = None;
        let mut current_header_lowercase = false;
        let mut current_base64_decode: Option<(u32, bool)> = None;
        let mut current_base64_data = false;
        let mut current_is_fast_pattern = false;        // 新增：跟踪当前pattern是否为fast pattern
        let mut fast_pattern_index: Option<usize> = None; // 新增：记录fast pattern的索引

        // 新增：双向检测相关变量
        let mut flow_direction = RuleFlowDirection::Any;      // 流向要求
        let mut status_codes: Vec<u16> = Vec::new();          // 状态码列表
        let mut requires_established = false;                 // 是否要求established连接
        
        // 辅助函数：保存当前pattern并开始新的
        // 注意：不能使用闭包，因为会捕获可变引用，导致借用冲突
        // 改为在需要的地方直接内联代码
        
        for option in options_str.split(';') {
            let option = option.trim();
            if option.is_empty() {
                continue;
            }
            
            if let Some(eq_pos) = option.find(':') {
                let key = &option[..eq_pos];
                let value = &option[eq_pos + 1..].trim_matches('"');
                
                match key {
                    "msg" => message = value.to_string(),
                    "flow" => {
                        // 解析flow选项，格式：flow:established,to_server 或 flow:to_client
                        for flow_part in value.split(',') {
                            match flow_part.trim() {
                                "established" => requires_established = true,
                                "to_server" => flow_direction = RuleFlowDirection::ToServer,
                                "to_client" => flow_direction = RuleFlowDirection::ToClient,
                                _ => {} // 忽略其他flow选项
                            }
                        }
                    }
                    "content" => {
                        // 如果已经有pattern，先保存前一个
                        if !current_pattern.is_empty() {
                            let hyperscan_flags = modifiers_to_hyperscan_flags(
                                current_nocase,
                                current_startswith,
                                current_endswith,
                            );

                            // 添加调试日志
                            log::debug!("Creating PatternWithLocation for pattern: '{}'", current_pattern);
                            log::debug!("  -> http_location: {:?}", current_http_location);
                            log::debug!("  -> is_fast_pattern: {}", current_is_fast_pattern);
                            log::debug!("  -> header_lowercase: {}", current_header_lowercase);
                            log::debug!("  -> base64_decode: {:?}", current_base64_decode);
                            log::debug!("  -> base64_data: {}", current_base64_data);

                            // 如果是fast pattern，记录其索引
                            if current_is_fast_pattern {
                                fast_pattern_index = Some(patterns.len());
                                log::debug!("  -> Recording fast pattern at index: {}", patterns.len());
                            }

                            patterns.push(PatternWithLocation {
                                pattern: current_pattern.clone(),
                                http_location: current_http_location,
                                is_fast_pattern: current_is_fast_pattern,  // 使用解析的fast_pattern状态
                                nocase: current_nocase,       // 使用解析的nocase状态
                                startswith: current_startswith,
                                endswith: current_endswith,
                                distance: current_distance,
                                depth: current_depth,
                                offset: current_offset,
                                within: current_within,
                                hyperscan_flags,             // 使用计算的flags
                                requires_fallback: false,     // 默认不需要fallback
                                header_lowercase: current_header_lowercase,
                                base64_decode: current_base64_decode,
                                base64_data: current_base64_data,
                            });
                            // 重置当前pattern状态（但保留http_location和其他修饰符，因为下一个content可能继承它们）
                            current_pattern.clear();
                            current_nocase = false;        // 重置nocase状态
                            current_startswith = false;
                            current_endswith = false;
                            current_distance = None;
                            current_depth = None;
                            current_offset = None;
                            current_within = None;
                            current_is_fast_pattern = false; // 重置fast_pattern状态
                            // 注意：不重置以下状态，因为下一个content可能继承它们：
                            // current_http_location - HTTP位置
                            // current_header_lowercase - 小写转换
                            // current_base64_decode - base64解码
                            // current_base64_data - base64数据匹配
                        }
                        // 处理Suricata规则中的十六进制编码（如 |28 29 20 7b|）
                        current_pattern = Self::_decode_suricata_content(value);

                        // 检查解码后的结果，处理特殊标记
                        if current_pattern.is_empty() {
                            return Err(WebScanError::RuleParsing(
                                format!("Empty content pattern at line {}", line_num)
                            ));
                        } else if current_pattern == "[HEX_CONTENT]" {
                            // 对于纯十六进制内容（如单字节），提取原始字节值
                            // 从原始content值中提取十六进制
                            if value.len() >= 3 && value.starts_with('|') && value.ends_with('|') {
                                let hex_part = &value[1..value.len()-1];
                                if let Ok(byte_val) = u8::from_str_radix(hex_part, 16) {
                                    // 创建匹配单个字节的模式
                                    current_pattern = format!("\\x{:02X}", byte_val);
                                } else {
                                    // 如果解析失败，使用通配符
                                    current_pattern = ".".to_string();
                                }
                            } else {
                                current_pattern = ".".to_string();
                            }
                        }
                    }
                    "sid" => {
                        sid = value.parse().map_err(|_| {
                            WebScanError::RuleParsing(
                                format!("Invalid SID '{}' at line {}", value, line_num)
                            )
                        })?;
                    }
                    "status_code" | "http.stat_code" | "http.response_code" => {
                        // 解析状态码，支持单个状态码或范围
                        for code_part in value.split(',') {
                            let code_part = code_part.trim();
                            if code_part.contains('-') {
                                // 处理状态码范围，如 400-499
                                let range_parts: Vec<&str> = code_part.split('-').collect();
                                if range_parts.len() == 2 {
                                    if let (Ok(start), Ok(end)) = (
                                        range_parts[0].parse::<u16>(),
                                        range_parts[1].parse::<u16>()
                                    ) {
                                        for code in start..=end {
                                            status_codes.push(code);
                                        }
                                    }
                                }
                            } else {
                                // 处理单个状态码
                                if let Ok(code) = code_part.parse::<u16>() {
                                    status_codes.push(code);
                                }
                            }
                        }
                    }
                    "pcre" => {
                        // PCRE选项：使用新的PCRE处理器处理
                        match self.pcre_processor.process_pcre_pattern(
                            value,
                            current_http_location,
                            current_startswith,
                            current_endswith,
                            current_distance,
                            current_depth,
                            current_offset,
                            current_within,
                        ) {
                            Ok(pcre_pattern) => {
                                // 对于Hyperscan兼容的PCRE，不需要创建content pattern
                                // PCRE模式会直接在get_hyperscan_patterns中处理
                                if current_pattern.is_empty() {
                                    match pcre_pattern.match_type {
                                        PcreMatchType::Hyperscan | PcreMatchType::ConvertedHyperscan => {
                                            // 不创建content pattern，让PCRE模式直接处理
                                            // current_pattern保持为空
                                        }
                                        PcreMatchType::RegexFallback => {
                                            // 对于需要fallback的PCRE，创建一个占位符content以便Hyperscan编译
                                            current_pattern = format!("PCRE_FALLBACK_{}", pcre_patterns.len() + 1);
                                        }
                                    }
                                }
                                // 将PCRE模式添加到临时列表
                                pcre_patterns.push(pcre_pattern);
                                log::debug!("Processed PCRE pattern and added to rule");
                            }
                            Err(e) => {
                                log::warn!("Failed to process PCRE pattern '{}' at line {}: {}", value, line_num, e);
                                // 继续处理其他选项，不中断规则解析
                            }
                        }
                    }
                    "http.method" => {
                        current_http_location = HttpMatchLocation::Method;
                    }
                    "http.uri" => {
                        current_http_location = HttpMatchLocation::Uri;
                    }
                    "http.uri.raw" => {
                        current_http_location = HttpMatchLocation::UriRaw;
                    }
                    "http.cookie" => {
                        current_http_location = HttpMatchLocation::Cookie;
                    }
                    "http.request_body" => {
                        current_http_location = HttpMatchLocation::RequestBody;
                    }
                    "http.request_header" => {
                        current_http_location = HttpMatchLocation::RequestHeader;
                    }
                    "http.header" => {
                        current_http_location = HttpMatchLocation::RequestHeader;
                        log::debug!("Setting http_location to RequestHeader due to http.header");
                    }
                    "header_lowercase" => {
                        current_header_lowercase = true;
                    }
                    "fast_pattern" => {
                        current_is_fast_pattern = true;
                        log::debug!("Setting fast_pattern flag for current pattern");
                    }
                    "base64_decode" => {
                        // 解析 base64_decode:offset X,relative
                        if let Some(offset_pos) = value.find("offset") {
                            let remaining = &value[offset_pos + 6..].trim();
                            if let Some(comma_pos) = remaining.find(',') {
                                let offset_str = remaining[..comma_pos].trim();
                                let relative_part = remaining[comma_pos + 1..].trim();
                                if let Ok(offset_val) = offset_str.parse::<u32>() {
                                    let is_relative = relative_part == "relative";
                                    current_base64_decode = Some((offset_val, is_relative));
                                }
                            }
                        } else {
                            log::warn!("Invalid base64_decode format: {}", value);
                        }
                    }
                    "base64_data" => {
                        current_base64_data = true;
                    }
                    "nocase" => {
                        current_nocase = true;
                    }
                    "startswith" => {
                        current_startswith = true;
                    }
                    "endswith" => {
                        current_endswith = true;
                    }
                    "distance" => {
                        current_distance = value.parse().ok();
                    }
                    "depth" => {
                        current_depth = value.parse().ok();
                    }
                    "offset" => {
                        current_offset = value.parse().ok();
                    }
                    "within" => {
                        current_within = value.parse().ok();
                    }
                    _ => {} // 忽略其他选项（如flow, fast_pattern, nocase等）
                }
            } else {
                // 没有等号的选项（如 startswith, endswith, http.uri, http.method等）
                match option {
                    "startswith" => current_startswith = true,
                    "endswith" => current_endswith = true,
                    "http.method" => current_http_location = HttpMatchLocation::Method,
                    "http.uri" => current_http_location = HttpMatchLocation::Uri,
                    "http.uri.raw" => current_http_location = HttpMatchLocation::UriRaw,
                    "http.cookie" => current_http_location = HttpMatchLocation::Cookie,
                    "http.request_body" => current_http_location = HttpMatchLocation::RequestBody,
                    "http.request_header" => current_http_location = HttpMatchLocation::RequestHeader,
                    _ => {} // 忽略其他标志选项
                }
            }
        }
        
        // 保存最后一个pattern
        if !current_pattern.is_empty() {
            let hyperscan_flags = modifiers_to_hyperscan_flags(
                current_nocase,
                current_startswith,
                current_endswith,
            );

            // 添加调试日志
            log::debug!("Creating final PatternWithLocation:");
            log::debug!("  pattern: '{}'", current_pattern);
            log::debug!("  http_location: {:?}", current_http_location);
            log::debug!("  is_fast_pattern: {}", current_is_fast_pattern);
            log::debug!("  header_lowercase: {}", current_header_lowercase);
            log::debug!("  base64_decode: {:?}", current_base64_decode);
            log::debug!("  base64_data: {}", current_base64_data);

            // 如果是fast pattern，记录其索引
            if current_is_fast_pattern {
                fast_pattern_index = Some(patterns.len());
                log::debug!("  -> Recording final fast pattern at index: {}", patterns.len());
            }

            patterns.push(PatternWithLocation {
                pattern: current_pattern.clone(),
                http_location: current_http_location,
                is_fast_pattern: current_is_fast_pattern,  // 使用解析的fast_pattern状态
                nocase: current_nocase,       // 使用解析的nocase状态
                startswith: current_startswith,
                endswith: current_endswith,
                distance: current_distance,
                depth: current_depth,
                offset: current_offset,
                within: current_within,
                hyperscan_flags,             // 使用计算的flags
                requires_fallback: false,     // 默认不需要fallback
                header_lowercase: current_header_lowercase,
                base64_decode: current_base64_decode,
                base64_data: current_base64_data,
            });
        }
        
        if sid == 0 {
            return Err(WebScanError::RuleParsing(
                format!("Missing or invalid SID at line {}", line_num)
            ));
        }
        
        // 如果没有 content patterns 但有 pcre patterns，这是允许的（纯 PCRE 规则）
        if patterns.is_empty() && pcre_patterns.is_empty() {
            return Err(WebScanError::RuleParsing(
                format!("Missing content pattern and PCRE pattern at line {}", line_num)
            ));
        }
        
        // 应用 startswith、endswith 等选项，转换为 Hyperscan 正则表达式
        // 注意：对于HTTP特定位置的规则，startswith/endswith不应该在pattern中添加^/$锚点
        // 因为^/$会匹配整个payload的开头/结尾，而不是HTTP部分的开头/结尾
        // 我们会在匹配后通过位置验证来处理startswith/endswith
        let mut processed_patterns = Vec::new();
        let mut first_pattern_for_hyperscan = String::new();
        
        for mut pattern_with_loc in patterns {
            let has_http_location = pattern_with_loc.http_location != HttpMatchLocation::Any;
            let pattern_startswith = if has_http_location { false } else { pattern_with_loc.startswith };
            let pattern_endswith = if has_http_location { false } else { pattern_with_loc.endswith };
            
            let processed_pattern = Self::_apply_pattern_modifiers(
                pattern_with_loc.pattern.clone(),
                pattern_startswith,
                pattern_endswith,
                pattern_with_loc.distance,
                pattern_with_loc.depth,
                pattern_with_loc.offset,
                pattern_with_loc.within,
            );
            
            // 保存处理后的pattern（用于位置验证）
            pattern_with_loc.pattern = processed_pattern.clone();
            processed_patterns.push(pattern_with_loc);
            
            // 第一个pattern用于Hyperscan编译（向后兼容）
            if first_pattern_for_hyperscan.is_empty() {
                first_pattern_for_hyperscan = processed_pattern;
            }
        }
        
        // 创建规则
        let mut rule = Rule::new(sid, action, message, first_pattern_for_hyperscan)?;
        // 设置patterns
        rule.patterns = processed_patterns;

        // 添加PCRE模式到规则
        for pcre_pattern in pcre_patterns {
            rule.add_pcre_pattern(pcre_pattern);
        }

        // 设置fast_pattern_index
        rule.fast_pattern_index = fast_pattern_index;

        // 设置双向检测字段
        rule.flow_direction = flow_direction;
        rule.status_codes = status_codes.clone();
        rule.requires_established = requires_established;

        // 向后兼容：设置第一个pattern的http_location和metadata
        if let Some(first_pattern) = rule.patterns.first() {
            rule.http_location = first_pattern.http_location;
            if first_pattern.startswith {
                rule.metadata.insert("startswith".to_string(), "true".to_string());
            }
            if first_pattern.endswith {
                rule.metadata.insert("endswith".to_string(), "true".to_string());
            }
        }

        // 调试信息：记录双向检测配置
        log::debug!("Rule {} flow configuration:", sid);
        log::debug!("  -> flow_direction: {:?}", flow_direction);
        log::debug!("  -> status_codes: {:?}", status_codes);
        log::debug!("  -> requires_established: {}", requires_established);

        Ok(rule)
    }

    /// 解码Suricata规则中的content值
    ///
    /// 处理Suricata规则中的特殊格式：
    /// - 十六进制编码：|28 29 20 7b| -> 转换为对应的字节
    /// - 混合格式：bash|20 2d|c -> bash -c（|20|是空格，|2d|是-）
    ///
    /// # 参数
    /// * `content` - Suricata规则中的content值
    ///
    /// # 返回值
    /// * `String` - 解码后的字符串，对二进制内容使用十六进制转义
    fn _decode_suricata_content(content: &str) -> String {
        let mut result = String::new();
        let mut i = 0;
        let bytes = content.as_bytes();
        let mut has_hex_content = false;

        while i < bytes.len() {
            if bytes[i] == b'|' {
                // 找到十六进制编码的开始
                let hex_start = i + 1;
                let mut hex_end = hex_start;

                // 查找结束的|
                while hex_end < bytes.len() && bytes[hex_end] != b'|' {
                    hex_end += 1;
                }

                if hex_end < bytes.len() {
                    // 提取十六进制部分
                    let hex_str = &content[hex_start..hex_end];
                    // 解析十六进制字节
                    let hex_bytes: Vec<&str> = hex_str.split_whitespace().collect();
                    for hex_byte in hex_bytes {
                        if let Ok(byte_val) = u8::from_str_radix(hex_byte, 16) {
                            has_hex_content = true;
                            // 对于所有十六进制字节，都使用转义序列
                            // 这样可以确保Hyperscan能够正确处理
                            result.push_str(&format!("\\x{:02X}", byte_val));
                        }
                    }
                    i = hex_end + 1;
                } else {
                    // 没有找到结束的|，作为普通字符处理
                    result.push(bytes[i] as char);
                    i += 1;
                }
            } else {
                result.push(bytes[i] as char);
                i += 1;
            }
        }

        // 如果解码后结果为空，但原始内容包含十六进制，返回一个单字节模式
        if result.is_empty() && has_hex_content {
            // 对于这种情况，使用一个特殊的标记
            "[HEX_CONTENT]".to_string()
        } else {
            result
        }
    }

    /// 应用模式修饰符，转换为 Hyperscan 正则表达式
    /// 
    /// 将 Suricata 规则中的 startswith、endswith、distance、depth、offset、within 等选项
    /// 转换为 Hyperscan 正则表达式。
    /// 
    /// # 参数
    /// * `pattern` - 原始模式字符串
    /// * `startswith` - 是否从开始匹配
    /// * `endswith` - 是否在结尾匹配
    /// * `distance` - 与前一个 content 的距离（字节数）
    /// * `depth` - 搜索深度（从开始位置）
    /// * `offset` - 偏移量
    /// * `within` - 搜索范围
    /// 
    /// # 返回值
    /// * `String` - 转换后的 Hyperscan 正则表达式
    fn _apply_pattern_modifiers(
        pattern: String,
        startswith: bool,
        endswith: bool,
        distance: Option<u32>,
        depth: Option<u32>,
        offset: Option<u32>,
        within: Option<u32>,
    ) -> String {
        let mut result = pattern;
        
        // 检查是否已经包含正则表达式特殊字符
        // 如果已经包含，说明是正则表达式，不需要转义
        // 如果不包含，需要转义特殊字符以作为字面字符串匹配
        let has_regex_chars = result.chars().any(|c| matches!(c, '^' | '$' | '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '|' | '\\'));
        
        // 如果模式不包含正则表达式特殊字符，且不是PCRE模式，则转义特殊字符
        // 但要注意：如果已经应用了 startswith 或 endswith，说明需要作为正则表达式处理
        if !has_regex_chars && !startswith && !endswith {
            // 转义特殊字符，使其作为字面字符串匹配
            result = regex_escape(&result);
        } else if !has_regex_chars {
            // 如果包含 startswith 或 endswith，需要转义特殊字符但保留位置锚点
            // 转义特殊字符（除了已经添加的 ^ 和 $）
            result = regex_escape(&result);
        }
        
        // 应用 startswith：在模式前添加 ^
        if startswith && !result.starts_with('^') {
            result = format!("^{}", result);
        }
        
        // 应用 endswith：在模式后添加 $
        if endswith && !result.ends_with('$') {
            result = format!("{}$", result);
        }
        
        // 应用 depth：限制搜索深度
        // depth 表示从开始位置最多搜索 depth 字节
        // 在 Hyperscan 中，可以使用 (?<=.{0,depth}) 或直接限制搜索范围
        // 简化处理：如果指定了 depth，且没有 startswith，可以添加 (?<=.{0,depth}) 前缀
        // 但 Hyperscan 可能不支持 lookbehind，所以这里先简化处理
        if let Some(_d) = depth {
            if !startswith {
                // depth 限制从开始位置搜索的深度
                // 在 Hyperscan 中，可以通过限制匹配位置来实现
                // 这里先记录到 metadata，后续可以在匹配时处理
                // 暂时不修改 pattern
            }
        }
        
        // 应用 offset：指定偏移量
        // offset 表示从开始位置的偏移量
        // 在 Hyperscan 中，可以通过 (?<=.{offset}) 来实现
        // 但 Hyperscan 可能不支持 lookbehind，所以这里先简化处理
        if let Some(_o) = offset {
            if !startswith {
                // offset 指定从开始位置的偏移量
                // 暂时不修改 pattern，后续可以在匹配时处理
            }
        }
        
        // 应用 distance：与前一个 content 的距离
        // distance 表示与前一个匹配的距离
        // 在 Suricata 中，多个 content 选项可以组合
        // 这里先简化处理，后续可以支持多个 content 的组合
        if let Some(_d) = distance {
            // distance 需要与前一个 content 配合使用
            // 暂时不修改 pattern，后续可以支持多个 content 的组合
        }
        
        // 应用 within：搜索范围
        // within 表示在指定范围内搜索
        // 在 Hyperscan 中，可以通过限制匹配位置来实现
        // 暂时不修改 pattern，后续可以在匹配时处理
        if let Some(_w) = within {
            // within 需要与前一个 content 配合使用
            // 暂时不修改 pattern，后续可以支持多个 content 的组合
        }
        
        result
    }

    /// 转义Hyperscan模式中的特殊字符
    /// 
    /// Hyperscan支持基本的正则表达式，但某些PCRE特性可能不支持。
    /// 这个函数尝试转义可能导致问题的字符。
    /// 
    /// # 参数
    /// * `pattern` - PCRE模式字符串
    /// 
    /// # 返回值
    /// * `String` - 转义后的模式字符串
    fn _escape_hyperscan_pattern(pattern: &str) -> String {
        // Hyperscan支持基本的正则表达式，但某些复杂的PCRE特性可能不支持
        // 这里尝试转义可能导致问题的字符
        // 注意：这是一个简化的处理，复杂的PCRE模式可能需要更复杂的转换
        
        // 首先处理字符类中的转义序列（如 [\s>]）
        let mut result = String::new();
        let mut in_char_class = false;
        let bytes = pattern.as_bytes();
        let mut i = 0;
        
        while i < bytes.len() {
            if bytes[i] == b'[' && (i == 0 || bytes[i-1] != b'\\') {
                in_char_class = true;
                result.push(bytes[i] as char);
                i += 1;
            } else if bytes[i] == b']' && (i == 0 || bytes[i-1] != b'\\') {
                in_char_class = false;
                result.push(bytes[i] as char);
                i += 1;
            } else if in_char_class && bytes[i] == b'\\' && i + 1 < bytes.len() {
                // 在字符类中处理转义序列
                match bytes[i + 1] {
                    b's' => {
                        // \s 在字符类中展开为空白字符
                        result.push_str(" \t\n\r");
                        i += 2;
                    }
                    b'S' => {
                        // \S 在字符类中不能直接使用，保留原样或跳过
                        result.push(bytes[i] as char);
                        result.push(bytes[i + 1] as char);
                        i += 2;
                    }
                    b'w' => {
                        // \w 在字符类中展开为单词字符
                        result.push_str("a-zA-Z0-9_");
                        i += 2;
                    }
                    b'W' => {
                        // \W 在字符类中不能直接使用，保留原样或跳过
                        result.push(bytes[i] as char);
                        result.push(bytes[i + 1] as char);
                        i += 2;
                    }
                    b'd' => {
                        // \d 在字符类中展开为数字
                        result.push_str("0-9");
                        i += 2;
                    }
                    b'D' => {
                        // \D 在字符类中不能直接使用，保留原样或跳过
                        result.push(bytes[i] as char);
                        result.push(bytes[i + 1] as char);
                        i += 2;
                    }
                    _ => {
                        result.push(bytes[i] as char);
                        i += 1;
                    }
                }
            } else {
                result.push(bytes[i] as char);
                i += 1;
            }
        }
        
        // 然后处理字符类外的转义序列
        result
            .replace(r"\W", r"[^a-zA-Z0-9_]")  // \W -> 非单词字符
            .replace(r"\w", r"[a-zA-Z0-9_]")   // \w -> 单词字符
            .replace(r"\d", r"[0-9]")          // \d -> 数字
            .replace(r"\D", r"[^0-9]")          // \D -> 非数字
            .replace(r"\s", r"[ \t\n\r]")      // \s -> 空白字符（字符类外）
            .replace(r"\S", r"[^ \t\n\r]")     // \S -> 非空白字符（字符类外）
    }

    /// 解析JSON格式的规则
    /// 
    /// # 参数
    /// * `json_content` - JSON格式的规则内容
    /// 
    /// # 返回值
    /// * `Result<u32>` - 成功返回解析的规则数量，失败返回错误
    fn parse_json_rules(&mut self, json_content: &str) -> Result<u32> {
        // 定义JSON规则的结构
        #[derive(Deserialize)]
        struct JsonRule {
            id: u32,
            action: String,
            message: String,
            pattern: String,
            #[serde(default)]
            metadata: HashMap<String, String>,
        }

        // 解析JSON数组
        let json_rules: Vec<JsonRule> = serde_json::from_str(json_content)?;
        let mut loaded_count = 0;

        // 遍历解析的规则
        for json_rule in json_rules {
            // 将字符串动作转换为RuleAction枚举
            let action = match json_rule.action.as_str() {
                "alert" => RuleAction::Alert,
                "drop" => RuleAction::Drop,
                "reset" => RuleAction::Reset,
                "none" => RuleAction::None,
                _ => return Err(WebScanError::RuleParsing(
                    format!("Invalid action '{}' for rule {}", json_rule.action, json_rule.id)
                )),
            };

            // 创建Rule实例
            let mut rule = Rule::new(
                json_rule.id,
                action,
                json_rule.message,
                json_rule.pattern,
            )?;

            // 添加元数据
            for (key, value) in json_rule.metadata {
                rule.add_metadata(key, value);
            }

            // 添加到规则管理器
            self.add_rule(rule)?;
            loaded_count += 1;
        }

        Ok(loaded_count)
    }

    /// 解析TOML格式的规则
    /// 
    /// # 参数
    /// * `toml_content` - TOML格式的规则内容
    /// 
    /// # 返回值
    /// * `Result<u32>` - 成功返回解析的规则数量，失败返回错误
    fn parse_toml_rules(&mut self, toml_content: &str) -> Result<u32> {
        // 定义TOML规则的结构
        #[derive(Deserialize)]
        struct TomlRule {
            id: u32,
            action: String,
            message: String,
            pattern: String,
            #[serde(default)]
            metadata: HashMap<String, String>,
        }

        #[derive(Deserialize)]
        struct TomlRules {
            rules: Vec<TomlRule>,
        }

        // 解析TOML内容
        let toml_rules: TomlRules = toml::from_str(toml_content)?;
        let mut loaded_count = 0;

        // 遍历解析的规则
        for toml_rule in toml_rules.rules {
            // 将字符串动作转换为RuleAction枚举
            let action = match toml_rule.action.as_str() {
                "alert" => RuleAction::Alert,
                "drop" => RuleAction::Drop,
                "reset" => RuleAction::Reset,
                "none" => RuleAction::None,
                _ => return Err(WebScanError::RuleParsing(
                    format!("Invalid action '{}' for rule {}", toml_rule.action, toml_rule.id)
                )),
            };

            // 创建Rule实例
            let mut rule = Rule::new(
                toml_rule.id,
                action,
                toml_rule.message,
                toml_rule.pattern,
            )?;

            // 添加元数据
            for (key, value) in toml_rule.metadata {
                rule.add_metadata(key, value);
            }

            // 添加到规则管理器
            self.add_rule(rule)?;
            loaded_count += 1;
        }

        Ok(loaded_count)
    }

    /// 启用或禁用规则管理
    /// 
    /// # 参数
    /// * `enabled` - 是否启用
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// 检查规则管理是否启用
    /// 
    /// # 返回值
    /// * `bool` - 如果启用返回true，否则返回false
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 清空所有规则
    /// 
    /// 移除所有已加载的规则，重置规则计数。
    pub fn clear_rules(&mut self) {
        self.rules.clear();              // 清空HashMap
        self.rule_count = 0;             // 重置计数
    }
}

/// ThreeLayerMatcher 的实现
impl ThreeLayerMatcher {
    /// 创建新的三层匹配器
    pub fn new() -> Self {
        Self {
            fast_pattern_db: None,
            full_content_db: None,
            regex_fallback_rules: std::collections::HashMap::new(),
            rule_metadata: std::collections::HashMap::new(),
        }
    }

    /// 编译规则到三层匹配系统
    pub fn compile_rules(&mut self, rules: &[Rule]) -> crate::error::Result<()> {
        use crate::hyperscan::HyperscanCompiler;

        // 创建编译器
        let mut compiler = HyperscanCompiler::new();

        // 分类规则并创建两个规则集合
        let mut full_rules = Vec::new();
        let mut fast_rules = Vec::new();
        let mut regex_fallback_map = std::collections::HashMap::new();

        for rule in rules {
            let mut metadata = RuleMetadata {
                has_fast_pattern: rule.fast_pattern_index.is_some(),
                fast_pattern_in_header: false,
                has_pcre_fallback: false,
                total_patterns: rule.patterns.len() + rule.pcre_patterns.len(),
            };

            // 检查是否有fast pattern且在HTTP header中
            if let Some(fast_pattern_idx) = rule.fast_pattern_index {
                if let Some(fast_pattern) = rule.patterns.get(fast_pattern_idx) {
                    metadata.fast_pattern_in_header = matches!(
                        fast_pattern.http_location,
                        HttpMatchLocation::RequestHeader |
                        HttpMatchLocation::Method |
                        HttpMatchLocation::Uri |
                        HttpMatchLocation::UriRaw |
                        HttpMatchLocation::Cookie
                    );
                }
            }

            // 处理PCRE patterns
            let mut regex_fallbacks = Vec::new();
            for pcre_pattern in &rule.pcre_patterns {
                if pcre_pattern.match_type == PcreMatchType::RegexFallback {
                    metadata.has_pcre_fallback = true;
                    regex_fallbacks.push(pcre_pattern.clone());
                }
            }

            // 添加规则到对应的列表
            full_rules.push(rule.clone());
            if metadata.fast_pattern_in_header {
                fast_rules.push(rule.clone());
            }

            // 保存元数据
            self.rule_metadata.insert(rule.id, metadata);

            // 如果有regex fallback patterns，保存到单独的map
            if !regex_fallbacks.is_empty() {
                regex_fallback_map.insert(rule.id, regex_fallbacks);
            }
        }

        // 编译完整数据库
        for rule in &full_rules {
            compiler.add_rule(rule)?;
        }

        let (full_db, fast_db) = compiler.compile()?;

        self.full_content_db = Some(full_db);
        self.fast_pattern_db = fast_db;
        self.regex_fallback_rules = regex_fallback_map;

        log::info!("ThreeLayerMatcher compiled: {} rules ({} with fast patterns)",
                   rules.len(), fast_rules.len());

        Ok(())
    }

    /// 执行三层匹配
    pub fn match_data(&self, data: &[u8], candidate_rule_ids: Option<&[u32]>) -> Vec<u32> {
        let mut matched_rules = std::collections::HashSet::new();

        // 将数据转换为字符串用于HTTP解析
        let data_str = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                log::warn!("Invalid UTF-8 data, skipping regex fallback");
                return Vec::new();
            }
        };

        // 第一层：Fast Pattern匹配（如果有候选规则限制）
        if let Some(candidate_ids) = candidate_rule_ids {
            if let Some(ref fast_db) = self.fast_pattern_db {
                // 只测试候选规则中的fast pattern
                if let Ok(scanner) = crate::hyperscan::HyperscanScanner::new(fast_db.clone(), None) {
                    if let Ok(matches) = scanner.scan_stream(data) {
                        for match_result in matches {
                            if candidate_ids.contains(&match_result.rule_id) {
                                matched_rules.insert(match_result.rule_id);
                            }
                        }
                    }
                }
            }
        } else {
            // 没有候选规则限制，使用full database
            if let Some(ref full_db) = self.full_content_db {
                if let Ok(scanner) = crate::hyperscan::HyperscanScanner::new(full_db.clone(), self.fast_pattern_db.clone()) {
                    if let Ok(matches) = scanner.scan_stream(data) {
                        for match_result in matches {
                            matched_rules.insert(match_result.rule_id);
                        }
                    }
                }
            }
        }

        // 第二层：完整模式验证（对于有fast pattern命中的规则）
        if !matched_rules.is_empty() {
            matched_rules.retain(|&rule_id| self.verify_rule_full_match(rule_id, data_str, data));
        }

        // 第三层：Regex Fallback匹配（对于没有在Hyperscan中匹配的规则）
        let regex_matches = self.regex_fallback_match(data_str);
        for rule_id in regex_matches {
            matched_rules.insert(rule_id);
        }

        matched_rules.into_iter().collect()
    }

    /// 验证规则的所有条件是否完全匹配
    #[allow(dead_code)]
    fn verify_rule_full_match(&self, rule_id: u32, data_str: &str, _data: &[u8]) -> bool {
        // 获取规则元数据
        if let Some(metadata) = self.rule_metadata.get(&rule_id) {
            // 如果有PCRE fallback patterns，需要验证它们
            if metadata.has_pcre_fallback {
                if let Some(pcre_patterns) = self.regex_fallback_rules.get(&rule_id) {
                    for pcre_pattern in pcre_patterns {
                        if let Some(target_content) = self.extract_http_content(data_str, pcre_pattern.http_location) {
                            if let Some(regex) = &pcre_pattern.compiled_regex {
                                if regex.is_match(target_content) {
                                    return true; // PCRE patterns匹配
                                }
                            }
                        }
                    }
                    return false; // 没有PCRE pattern匹配
                }
            }
        }

        // 对于没有PCRE fallback的规则，假设已经通过Hyperscan验证
        true
    }

    /// Regex fallback匹配
    fn regex_fallback_match(&self, data_str: &str) -> Vec<u32> {
        let mut matched_rules = Vec::new();

        for (&rule_id, pcre_patterns) in &self.regex_fallback_rules {
            for pcre_pattern in pcre_patterns {
                if let Some(target_content) = self.extract_http_content(data_str, pcre_pattern.http_location) {
                    if let Some(regex) = &pcre_pattern.compiled_regex {
                        if regex.is_match(target_content) {
                            matched_rules.push(rule_id);
                            break; // 一个规则匹配就够了
                        }
                    }
                }
            }
        }

        matched_rules
    }

    /// 从HTTP数据中提取指定内容
    fn extract_http_content<'a>(&self, data: &'a str, location: HttpMatchLocation) -> Option<&'a str> {
        match location {
            HttpMatchLocation::Any => Some(data),
            HttpMatchLocation::Method => {
                data.split_whitespace().next()
            }
            HttpMatchLocation::Uri | HttpMatchLocation::UriRaw => {
                if let Some(method) = data.split_whitespace().next() {
                    let after_method = &data[method.len()..].trim_start();
                    after_method.split_whitespace().next()
                } else {
                    None
                }
            }
            HttpMatchLocation::RequestHeader => {
                if let Some(header_end) = data.find("\r\n\r\n") {
                    Some(&data[..header_end])
                } else {
                    None
                }
            }
            HttpMatchLocation::Cookie => {
                if let Some(cookie_line) = data.lines().find(|line| line.to_lowercase().starts_with("cookie:")) {
                    Some(&cookie_line[7..].trim()) // 跳过"Cookie:"
                } else {
                    None
                }
            }
            HttpMatchLocation::RequestBody => {
                if let Some(header_end) = data.find("\r\n\r\n") {
                    Some(&data[header_end + 4..])
                } else {
                    None
                }
            }
        }
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> (usize, usize, usize) {
        let fast_patterns = self.fast_pattern_db.as_ref()
            .map(|_| 0) // HyperscanDatabase 当前不支持模式计数，返回0
            .unwrap_or(0);
        let full_patterns = self.full_content_db.as_ref()
            .map(|_| 0) // HyperscanDatabase 当前不支持模式计数，返回0
            .unwrap_or(0);
        let regex_rules = self.regex_fallback_rules.len();

        (fast_patterns, full_patterns, regex_rules)
    }
}

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    // 导入父模块的所有公共项
    use super::*;

    /// 测试规则创建和匹配
    #[test]
    fn test_rule_creation_and_matching() {
        // 创建测试规则
        let rule = Rule::new(
            1,
            RuleAction::Alert,
            "Test rule".to_string(),
            "test".to_string(),
        ).unwrap();

        // 测试匹配功能
        assert!(rule.matches("This is a test message"));
        assert!(!rule.matches("This message doesn't contain the pattern"));
    }

    /// 测试规则管理器
    #[test]
    fn test_rule_manager() {
        let mut manager = RuleManager::new();
        
        // 创建测试规则
        let rule1 = Rule::new(1, RuleAction::Alert, "Rule 1".to_string(), "pattern1".to_string()).unwrap();
        let rule2 = Rule::new(2, RuleAction::Drop, "Rule 2".to_string(), "pattern2".to_string()).unwrap();
        
        // 添加规则
        manager.add_rule(rule1).unwrap();
        manager.add_rule(rule2).unwrap();
        
        // 验证规则数量
        assert_eq!(manager.rule_count(), 2);
        
        // 测试内容匹配
        assert!(manager.match_content("This contains pattern1").is_some());
        assert!(manager.match_content("This contains pattern2").is_some());
        assert!(manager.match_content("This contains nothing").is_none());
    }

    /// 测试重复规则ID的处理
    #[test]
    fn test_duplicate_rule_id() {
        let mut manager = RuleManager::new();
        
        let rule1 = Rule::new(1, RuleAction::Alert, "Rule 1".to_string(), "pattern1".to_string()).unwrap();
        let rule2 = Rule::new(1, RuleAction::Drop, "Rule 2".to_string(), "pattern2".to_string()).unwrap();
        
        // 第一个规则应该成功添加
        manager.add_rule(rule1).unwrap();
        
        // 第二个规则应该失败（ID重复）
        assert!(manager.add_rule(rule2).is_err());
    }
}