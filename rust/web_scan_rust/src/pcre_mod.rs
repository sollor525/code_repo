//! PCRE（Perl Compatible Regular Expressions）处理模块
//!
//! 提供PCRE字段的解析、转换和匹配功能。
//! 实现分层处理机制：
//! 1. Hyperscan兼容的正则表达式直接编译为Hyperscan规则
//! 2. 不兼容的正则表达式尝试转换为Hyperscan兼容格式
//! 3. 无法转换的使用regex crate进行fallback匹配

use crate::error::{Result, WebScanError};
use crate::rules::HttpMatchLocation;
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;

/// PCRE匹配类型
#[derive(Debug, Clone, PartialEq)]
pub enum PcreMatchType {
    /// Hyperscan直接匹配（高性能）
    Hyperscan,
    /// 转换后的Hyperscan匹配（中等性能）
    ConvertedHyperscan,
    /// Regex crate fallback匹配（低性能）
    RegexFallback,
}

/// PCRE标志位
#[derive(Debug, Clone, Default)]
pub struct PcreFlags {
    pub ignore_case: bool,     // i - 忽略大小写
    pub single_line: bool,     // s - 单行模式（.匹配换行符）
    pub multi_line: bool,      // m - 多行模式（^和$匹配行边界）
    pub extended: bool,        // x - 忽略空白和注释
}

/// PCRE模式信息
#[derive(Debug, Clone)]
pub struct PcrePattern {
    /// 原始PCRE模式字符串
    pub raw_pattern: String,
    /// 处理后的模式（用于Hyperscan或regex）
    pub processed_pattern: String,
    /// PCRE标志位
    pub flags: PcreFlags,
    /// 匹配类型
    pub match_type: PcreMatchType,
    /// 编译后的regex（仅用于fallback）
    pub compiled_regex: Option<Regex>,
    /// HTTP匹配位置
    pub http_location: HttpMatchLocation,
    /// 模式修饰符
    pub startswith: bool,
    pub endswith: bool,
    pub distance: Option<u32>,
    pub depth: Option<u32>,
    pub offset: Option<u32>,
    pub within: Option<u32>,
}

/// Hyperscan不支持的PCRE特性列表
const HYPERSCAN_UNSUPPORTED_FEATURES: &[&str] = &[
    r"\A",   // 字符串开始锚点
    r"\z",   // 字符串结束锚点
    r"\Z",   // 字符串结束或换行前锚点
    r"(?<!", // 否定逆序环视
    r"(?<=", // 逆序环视
    r"(?P<", // 命名捕获组
    r"(?(",  // 条件匹配
    r"(?#",  // 注释
    r"\K",   // 重置匹配起始位置
    r"\R",   // 通用换行符
    r"\X",   // Unicode扩展字符序列
];

/// Hyperscan支持的正则表达式特性
const HYPERSCAN_SUPPORTED_FEATURES: &[&str] = &[
    r".", "*", "+", "?", "|",     // 基本元字符
    r"^", "$",                    // 行锚点
    r"[", "]", "(", ")",          // 字符类和分组
    r"{", "}",                    // 量词
    r"\d", "\w", "\s",           // 简写字符类
    r"\D", "\W", "\S",           // 否定简写字符类
    r"[", "]", "(", ")",         // 字符类和分组
    r"|",                        // 选择
];

/// PCRE处理器
pub struct PcreProcessor {
    /// 缓存已编译的正则表达式
    regex_cache: HashMap<String, Regex>,
    /// Hyperscan模式缓存
    hyperscan_pattern_cache: HashMap<String, String>,
}

impl PcreProcessor {
    /// 创建新的PCRE处理器
    pub fn new() -> Self {
        Self {
            regex_cache: HashMap::new(),
            hyperscan_pattern_cache: HashMap::new(),
        }
    }

    /// 解析PCRE规则字符串
    ///
    /// # 参数
    /// * `pcre_str` - PCRE规则字符串，如 "/pattern/flags" 或 "pattern"
    ///
    /// # 返回值
    /// * `Result<(String, PcreFlags)>` - 解析后的模式和标志
    pub fn parse_pcre_string(pcre_str: &str) -> Result<(String, PcreFlags)> {
        let trimmed = pcre_str.trim_matches('"');

        if trimmed.starts_with('/') && trimmed.len() > 1 {
            // 标准格式：/pattern/flags
            let pcre_without_first_slash = &trimmed[1..];
            if let Some(flags_pos) = pcre_without_first_slash.rfind('/') {
                let pattern = pcre_without_first_slash[..flags_pos].to_string();
                let flags_str = &pcre_without_first_slash[flags_pos + 1..];
                let flags = Self::parse_flags(flags_str)?;
                Ok((pattern, flags))
            } else {
                // 只有开始斜杠，没有结束斜杠
                Ok((pcre_without_first_slash.to_string(), PcreFlags::default()))
            }
        } else {
            // 简化格式：直接使用字符串作为模式
            Ok((trimmed.to_string(), PcreFlags::default()))
        }
    }

    /// 解析PCRE标志字符串
    ///
    /// # 参数
    /// * `flags_str` - 标志字符串
    ///
    /// # 返回值
    /// * `Result<PcreFlags>` - 解析后的标志
    fn parse_flags(flags_str: &str) -> Result<PcreFlags> {
        let mut flags = PcreFlags::default();

        for ch in flags_str.chars() {
            match ch {
                'i' => flags.ignore_case = true,
                's' => flags.single_line = true,
                'm' => flags.multi_line = true,
                'x' => flags.extended = true,
                _ => {
                    log::warn!("Unsupported PCRE flag: '{}'", ch);
                    // 继续处理其他标志，不报错
                }
            }
        }

        Ok(flags)
    }

    /// 检查正则表达式是否与Hyperscan兼容
    ///
    /// # 参数
    /// * `pattern` - 正则表达式模式
    ///
    /// # 返回值
    /// * `bool` - 如果兼容返回true
    pub fn is_hyperscan_compatible(pattern: &str) -> bool {
        // 检查是否包含Hyperscan不支持的特性
        for unsupported_feature in HYPERSCAN_UNSUPPORTED_FEATURES {
            if pattern.contains(unsupported_feature) {
                log::debug!("Pattern '{}' contains unsupported feature '{}'", pattern, unsupported_feature);
                return false;
            }
        }

        // 检查平衡性（括号、方括号等）
        if !Self::is_balanced(pattern) {
            log::debug!("Pattern '{}' has unbalanced brackets/parentheses", pattern);
            return false;
        }

        log::debug!("Pattern '{}' appears to be Hyperscan compatible", pattern);
        true
    }

    /// 检查正则表达式的括号平衡性
    ///
    /// # 参数
    /// * `pattern` - 正则表达式模式
    ///
    /// # 返回值
    /// * `bool` - 如果平衡返回true
    fn is_balanced(pattern: &str) -> bool {
        let mut parentheses = 0i32;
        let mut brackets = 0i32;
        let mut braces = 0i32;
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            match ch {
                '\\' => {
                    // 跳过转义字符
                    if i + 1 < chars.len() {
                        i += 2;
                        continue;
                    }
                }
                '(' => parentheses += 1,
                ')' => parentheses -= 1,
                '[' => brackets += 1,
                ']' => brackets -= 1,
                '{' => braces += 1,
                '}' => braces -= 1,
                _ => {}
            }

            // 检查是否出现负数
            if parentheses < 0 || brackets < 0 || braces < 0 {
                return false;
            }

            i += 1;
        }

        parentheses == 0 && brackets == 0 && braces == 0
    }

    /// 尝试将PCRE模式转换为Hyperscan兼容格式
    ///
    /// # 参数
    /// * `pattern` - 原始PCRE模式
    ///
    /// # 返回值
    /// * `Result<String>` - 转换后的模式，如果无法转换则返回错误
    pub fn convert_to_hyperscan(pattern: &str) -> Result<String> {
        let mut converted = pattern.to_string();

        // 替换不支持的特性
        let replacements = [
            (r"\A", "^"),           // 字符串开始锚点 -> 行开始锚点
            (r"\z", r"$"),          // 字符串结束锚点 -> 行结束锚点
            (r"\Z", r"$"),          // 字符串结束或换行前锚点 -> 行结束锚点
            (r"\R", r"(?:\r\n|\n|\r)"), // 通用换行符 -> 具体换行符组合
        ];

        for (unsupported, replacement) in &replacements {
            converted = converted.replace(unsupported, replacement);
        }

        // 检查不支持的特性并返回错误（让调用者决定使用fallback）
        if converted.contains(r"(?<=") || converted.contains(r"(?<!") {
            return Err(WebScanError::RuleParsing(
                "Lookbehind assertions are not supported by Hyperscan".to_string()
            ));
        }

        if converted.contains(r"(?P<") {
            return Err(WebScanError::RuleParsing(
                "Named capture groups are not supported by Hyperscan".to_string()
            ));
        }

        if converted.contains(r"(?(") {
            return Err(WebScanError::RuleParsing(
                "Conditional expressions are not supported by Hyperscan".to_string()
            ));
        }

        if converted.contains(r"\K") {
            return Err(WebScanError::RuleParsing(
                "\\K reset is not supported by Hyperscan".to_string()
            ));
        }

        if converted.contains(r"\X") {
            return Err(WebScanError::RuleParsing(
                "\\X Unicode extended grapheme clusters are not supported by Hyperscan".to_string()
            ));
        }

        // 检查注释
        if converted.contains(r"(?#") {
            return Err(WebScanError::RuleParsing(
                "Comments are not supported by Hyperscan".to_string()
            ));
        }

        Ok(converted)
    }

    /// 编译正则表达式用于fallback匹配
    ///
    /// # 参数
    /// * `pattern` - 正则表达式模式
    /// * `flags` - PCRE标志
    ///
    /// # 返回值
    /// * `Result<Regex>` - 编译后的正则表达式
    pub fn compile_regex_fallback(pattern: &str, flags: &PcreFlags) -> Result<Regex> {
        let mut builder = RegexBuilder::new(pattern);

        // 应用PCRE标志到regex builder
        if flags.ignore_case {
            builder.case_insensitive(true);
        }

        if flags.single_line {
            // . 应该匹配换行符
            builder.dot_matches_new_line(true);
        }

        if flags.multi_line {
            // ^ 和 $ 应该匹配行边界
            builder.multi_line(true);
        }

        if flags.extended {
            // 忽略空白，需要预处理模式
            let pattern = Self::remove_whitespace_and_comments(pattern);
            builder = RegexBuilder::new(&pattern);
        }

        builder.build()
            .map_err(|e| WebScanError::RuleParsing(
                format!("Failed to compile regex fallback '{}': {}", pattern, e)
            ))
    }

    /// 移除正则表达式中的空白和注释（扩展模式）
    ///
    /// # 参数
    /// * `pattern` - 原始模式
    ///
    /// # 返回值
    /// * `String` - 处理后的模式
    fn remove_whitespace_and_comments(pattern: &str) -> String {
        let mut result = String::new();
        let mut in_char_class = false;
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            match ch {
                '\\' => {
                    // 保留转义序列
                    result.push(ch);
                    if i + 1 < chars.len() {
                        result.push(chars[i + 1]);
                        i += 1;
                    }
                }
                '[' => {
                    in_char_class = true;
                    result.push(ch);
                }
                ']' => {
                    in_char_class = false;
                    result.push(ch);
                }
                '#' if !in_char_class => {
                    // 跳过注释到行尾
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                    }
                }
                ' ' | '\t' | '\n' | '\r' if !in_char_class => {
                    // 跳过空白
                }
                _ => {
                    result.push(ch);
                }
            }

            i += 1;
        }

        result
    }

    /// 处理PCRE模式，确定匹配策略
    ///
    /// # 参数
    /// * `pcre_str` - PCRE字符串
    /// * `http_location` - HTTP匹配位置
    /// * `startswith` - 是否要求开始匹配
    /// * `endswith` - 是否要求结尾匹配
    /// * `distance` - 距离修饰符
    /// * `depth` - 深度修饰符
    /// * `offset` - 偏移修饰符
    /// * `within` - 范围修饰符
    ///
    /// # 返回值
    /// * `Result<PcrePattern>` - 处理后的PCRE模式
    pub fn process_pcre_pattern(
        &mut self,
        pcre_str: &str,
        http_location: HttpMatchLocation,
        startswith: bool,
        endswith: bool,
        distance: Option<u32>,
        depth: Option<u32>,
        offset: Option<u32>,
        within: Option<u32>,
    ) -> Result<PcrePattern> {
        // 解析PCRE字符串
        let (raw_pattern, flags) = Self::parse_pcre_string(pcre_str)?;
        log::debug!("Processing PCRE pattern: '{}' -> raw: '{}', flags: {:?}", pcre_str, raw_pattern, flags);

        // 检查Hyperscan兼容性
        let is_compatible = Self::is_hyperscan_compatible(&raw_pattern);
        log::debug!("Pattern '{}' is Hyperscan compatible: {}", raw_pattern, is_compatible);
        
        let (match_type, processed_pattern) = if is_compatible {
            // 直接兼容Hyperscan
            (PcreMatchType::Hyperscan, raw_pattern.to_string())
        } else {
            // 尝试转换为Hyperscan兼容格式
            match Self::convert_to_hyperscan(&raw_pattern) {
                Ok(converted) => {
                    log::info!("Converted PCRE pattern '{}' to Hyperscan-compatible '{}'", raw_pattern, converted);
                    (PcreMatchType::ConvertedHyperscan, converted)
                }
                Err(e) => {
                    log::warn!("Failed to convert PCRE pattern '{}' to Hyperscan: {}, using regex fallback", raw_pattern, e);
                    (PcreMatchType::RegexFallback, raw_pattern.to_string())
                }
            }
        };

        log::debug!("Pattern '{}' will use match type: {:?}", raw_pattern, match_type);

        // 如果是fallback模式，编译正则表达式
        let compiled_regex = if match_type == PcreMatchType::RegexFallback {
            let cache_key = format!("{}:{}:{}:{}:{}", raw_pattern, flags.ignore_case, flags.single_line, flags.multi_line, flags.extended);

            if let Some(cached_regex) = self.regex_cache.get(&cache_key) {
                Some(cached_regex.clone())
            } else {
                match Self::compile_regex_fallback(&raw_pattern, &flags) {
                    Ok(regex) => {
                        self.regex_cache.insert(cache_key.clone(), regex.clone());
                        Some(regex)
                    }
                    Err(e) => {
                        log::warn!("Failed to compile regex fallback for '{}': {}, using pattern without compilation", raw_pattern, e);
                        // 即使编译失败，也返回None而不是错误，允许模式被处理
                        None
                    }
                }
            }
        } else {
            None
        };

        Ok(PcrePattern {
            raw_pattern: raw_pattern.to_string(),
            processed_pattern,
            flags,
            match_type,
            compiled_regex,
            http_location,
            startswith,
            endswith,
            distance,
            depth,
            offset,
            within,
        })
    }
}

impl Default for PcreProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcre_parsing() {
        // 测试标准格式
        let (pattern, flags) = PcreProcessor::parse_pcre_string("/test/i").unwrap();
        assert_eq!(pattern, "test");
        assert!(flags.ignore_case);
        assert!(!flags.single_line);

        // 测试简化格式
        let (pattern, flags) = PcreProcessor::parse_pcre_string("test").unwrap();
        assert_eq!(pattern, "test");
        assert!(!flags.ignore_case);
    }

    #[test]
    fn test_hyperscan_compatibility() {
        // 兼容的模式
        assert!(PcreProcessor::is_hyperscan_compatible(r"test.*pattern"));
        assert!(PcreProcessor::is_hyperscan_compatible(r"\d+"));
        assert!(PcreProcessor::is_hyperscan_compatible(r"(test|pattern)"));

        // 不兼容的模式
        assert!(!PcreProcessor::is_hyperscan_compatible(r"(?<=test)pattern"));
        assert!(!PcreProcessor::is_hyperscan_compatible(r"(?P<name>test)"));
        assert!(!PcreProcessor::is_hyperscan_compatible(r"test\Kpattern"));
    }

    #[test]
    fn test_pattern_conversion() {
        // 测试可转换的模式
        let converted = PcreProcessor::convert_to_hyperscan(r"\Atest").unwrap();
        assert_eq!(converted, "^test");

        let converted = PcreProcessor::convert_to_hyperscan(r"test\z").unwrap();
        assert_eq!(converted, "test$");

        // 测试不可转换的模式
        assert!(PcreProcessor::convert_to_hyperscan(r"(?<=test)pattern").is_err());
        assert!(PcreProcessor::convert_to_hyperscan(r"(?P<name>test)").is_err());
    }

    #[test]
    fn test_regex_fallback() {
        let flags = PcreFlags {
            ignore_case: true,
            ..Default::default()
        };

        let regex = PcreProcessor::compile_regex_fallback("test", &flags).unwrap();
        assert!(regex.is_match("TEST"));
        assert!(regex.is_match("test"));
    }

    #[test]
    fn test_pcre_processing() {
        let mut processor = PcreProcessor::new();

        // 测试Hyperscan兼容的模式
        let pcre = processor.process_pcre_pattern(
            "/test/i",
            HttpMatchLocation::Any,
            false,
            false,
            None,
            None,
            None,
            None,
        ).unwrap();

        assert_eq!(pcre.raw_pattern, "test");
        assert!(pcre.flags.ignore_case);
        assert_eq!(pcre.match_type, PcreMatchType::Hyperscan);

        // 测试需要fallback的模式
        let pcre = processor.process_pcre_pattern(
            "/(?<=test)pattern/",
            HttpMatchLocation::Any,
            false,
            false,
            None,
            None,
            None,
            None,
        ).unwrap();

        assert_eq!(pcre.match_type, PcreMatchType::RegexFallback);
        assert!(pcre.compiled_regex.is_some());
    }

    #[test]
    fn test_balanced_patterns() {
        assert!(PcreProcessor::is_balanced(r"(test)"));
        assert!(PcreProcessor::is_balanced(r"[test]"));
        assert!(PcreProcessor::is_balanced(r"{test}"));

        assert!(!PcreProcessor::is_balanced(r"(test"));
        assert!(!PcreProcessor::is_balanced(r"test)"));
        assert!(!PcreProcessor::is_balanced(r"[test"));
        assert!(!PcreProcessor::is_balanced(r"test]"));
    }
}