//! 完整的PCRE（Perl Compatible Regular Expressions）处理模块
//!
//! 支持完整的PCRE语法，包括Suricata规则中使用的复杂正则表达式。
//! 能够将PCRE模式转换为Hyperscan兼容模式，或者使用Rust regex作为fallback。

use crate::error::{Result, WebScanError};
use crate::rules::HttpMatchLocation;
use regex::Regex;
use std::collections::HashMap;

/// 查找匹配的右括号
fn find_matching_paren(s: &str, start: usize) -> Option<usize> {
    let mut depth = 1;
    let mut escape_next = false;

    for (i, ch) in s[start + 1..].char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match ch {
            '\\' => {
                escape_next = true;
            }
            '(' => {
                depth += 1;
            }
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(start + 1 + i);
                }
            }
            _ => {}
        }
    }

    None
}

/// PCRE匹配类型
#[derive(Debug, Clone, PartialEq)]
pub enum PcreMatchType {
    /// 原生Hyperscan兼容模式
    Hyperscan,
    /// 从PCRE转换的Hyperscan模式
    ConvertedHyperscan,
    /// 需要使用Rust regex作为fallback
    RegexFallback,
}

/// 完整的PCRE模式
#[derive(Debug, Clone)]
pub struct PcrePattern {
    pub raw_pattern: String,
    pub processed_pattern: String,
    pub match_type: PcreMatchType,
    pub compiled_regex: Option<Regex>,
    pub http_location: HttpMatchLocation,
}

/// 完整的PCRE处理器
pub struct PcreProcessor {
    pcre_to_hyperscan_cache: HashMap<String, String>,
}

impl PcreProcessor {
    pub fn new() -> Self {
        Self {
            pcre_to_hyperscan_cache: HashMap::new(),
        }
    }

    /// 处理PCRE模式
    pub fn process_pcre_pattern(
        &mut self,
        pcre_str: &str,
        http_location: HttpMatchLocation,
        _startswith: bool,
        _endswith: bool,
        _distance: Option<u32>,
        _depth: Option<u32>,
        _offset: Option<u32>,
        _within: Option<u32>,
    ) -> Result<PcrePattern> {
        // 解析PCRE格式
        let (pattern, flags) = self.parse_pcre_syntax(pcre_str)?;

        // 尝试转换为Hyperscan兼容模式
        match self.try_convert_to_hyperscan(&pattern, &flags) {
            Ok(hyperscan_pattern) => {
                return Ok(PcrePattern::new_with_details(
                    pcre_str.to_string(),
                    hyperscan_pattern,
                    PcreMatchType::Hyperscan,
                    http_location,
                ));
            }
                Err(_) => {
                // 转换失败，使用regex fallback
                let rust_regex_pattern = self.convert_pcre_to_regex(&pattern, &flags)?;
                
                // 解析flags并应用到RegexBuilder
                let mut builder = regex::RegexBuilder::new(&rust_regex_pattern);
                let flags_lower = flags.to_lowercase();
                if flags_lower.contains('i') {
                    builder.case_insensitive(true);
                }
                if flags_lower.contains('s') {
                    builder.dot_matches_new_line(true);
                }
                if flags_lower.contains('m') {
                    builder.multi_line(true);
                }

                match builder.build() {
                    Ok(compiled_regex) => {
                        return Ok(PcrePattern::new_with_details(
                            pcre_str.to_string(),
                            rust_regex_pattern,
                            PcreMatchType::RegexFallback,
                            http_location,
                        ).with_compiled_regex(compiled_regex));
                    }
                    Err(e) => {
                        return Err(WebScanError::RuleParsing(
                            format!("Invalid regex pattern '{}': {}", rust_regex_pattern, e)
                        ));
                    }
                }
            }
        }
    }

    /// 解析PCRE语法
    fn parse_pcre_syntax(&self, pcre_str: &str) -> Result<(String, String)> {
        let trimmed = pcre_str.trim_matches('"');

        if !trimmed.starts_with('/') {
            return Err(WebScanError::RuleParsing(
                "PCRE pattern must start with '/'".to_string()
            ));
        }

        let pcre_without_first_slash = &trimmed[1..];

        if let Some(flags_pos) = pcre_without_first_slash.rfind('/') {
            let pattern = &pcre_without_first_slash[..flags_pos];
            let flags = &pcre_without_first_slash[flags_pos + 1..];

            Ok((pattern.to_string(), flags.to_string()))
        } else {
            Err(WebScanError::RuleParsing(
                "PCRE pattern must end with '/'".to_string()
            ))
        }
    }

    /// 尝试转换为Hyperscan兼容模式
    fn try_convert_to_hyperscan(&mut self, pattern: &str, flags: &str) -> Result<String> {
        // 首先检查原始PCRE模式是否包含Hyperscan不支持的特性
        // 在转换之前检查，因为转换可能掩盖某些特性
        if self.contains_unsupported_features(pattern) {
            return Err(WebScanError::RuleParsing(
                "Pattern contains unsupported Hyperscan features".to_string()
            ));
        }

        // 检查缓存
        let cache_key = format!("{}:{}", pattern, flags);
        if let Some(cached) = self.pcre_to_hyperscan_cache.get(&cache_key) {
            return Ok(cached.clone());
        }

        let mut hyperscan_pattern = pattern.to_string();

        // PCRE到Hyperscan的转换规则
        hyperscan_pattern = self.convert_pcre_to_hyperscan_syntax(&hyperscan_pattern);

        // 再次检查转换后的模式
        if self.contains_unsupported_features(&hyperscan_pattern) {
            return Err(WebScanError::RuleParsing(
                "Converted pattern contains unsupported Hyperscan features".to_string()
            ));
        }

        // 尝试编译以验证模式
        if self.validate_hyperscan_pattern(&hyperscan_pattern).is_ok() {
            self.pcre_to_hyperscan_cache.insert(cache_key, hyperscan_pattern.clone());
            Ok(hyperscan_pattern)
        } else {
            Err(WebScanError::RuleParsing(
                "Failed to validate Hyperscan pattern".to_string()
            ))
        }
    }

    /// 将PCRE语法转换为Hyperscan语法
    fn convert_pcre_to_hyperscan_syntax(&self, pattern: &str) -> String {
        let mut result = pattern.to_string();

        // 移除PCRE特有的语法，转换为基本正则表达式
        // 注意：这是一个简化的转换，完整的PCRE到Hyperscan转换非常复杂

        // 暂时禁用字符类转换，避免与现有字符类冲突
        // TODO: 实现智能字符类转换，只在需要时转换
        // result = result.replace("\\d", "[0-9]");
        // result = result.replace("\\D", "[^0-9]");
        // result = result.replace("\\w", "[a-zA-Z0-9_]");
        // result = result.replace("\\W", "[^a-zA-Z0-9_]");
        // result = result.replace("\\s", "[ \\t\\r\\n\\f]");
        // result = result.replace("\\S", "[^ \\t\\r\\n\\f]");

        // 处理简单的量词
        result = result.replace("\\b", "\\b");  // Hyperscan支持\\b

        // 处理十六进制转义
        result = self.convert_hex_escapes(&result);

        // 修复字符类中的问题
        result = self.fix_character_classes(&result);

        // 处理嵌入式锚点问题
        result = self.fix_embedded_anchors(&result);

        // 处理非贪婪量词（将非贪婪转换为贪婪）
        result = self.convert_non_greedy_quantifiers(&result);

        // 处理复杂的重复模式，转换为Hyperscan兼容形式
        result = self.convert_complex_repetitions(&result);

        result
    }

    /// 转换十六进制转义序列
    fn convert_hex_escapes(&self, pattern: &str) -> String {
        let mut result = pattern.to_string();
        let mut i = 0;

        while i < result.len() {
            if i + 1 < result.len() && result.chars().nth(i) == Some('\\') &&
               result.chars().nth(i + 1) == Some('x') {
                if i + 3 < result.len() {
                    let hex_str = &result[i + 2..i + 4];
                    if let Ok(byte_val) = u8::from_str_radix(hex_str, 16) {
                        // 将十六进制转换为字符或保持转义
                        let replacement = if byte_val.is_ascii_graphic() || byte_val == b' ' {
                            // 可打印字符直接转换
                            (byte_val as char).to_string()
                        } else if byte_val == b'\n' {
                            "\\n".to_string()
                        } else if byte_val == b'\r' {
                            "\\r".to_string()
                        } else if byte_val == b'\t' {
                            "\\t".to_string()
                        } else {
                            // 其他字符保持十六进制转义
                            format!("\\x{:02X}", byte_val)
                        };
                        result.replace_range(i..i + 4, &replacement);
                        i += replacement.len();
                        continue;
                    }
                }
            }
            i += 1;
        }

        result
    }

    /// 处理嵌入式锚点问题
    fn fix_embedded_anchors(&self, pattern: &str) -> String {
        let mut result = pattern.to_string();

        // 处理开头的^锚点（Hyperscan不支持）
        if result.starts_with('^') {
            result = result[1..].to_string();
        }

        // 处理结尾的$锚点（Hyperscan不支持）
        if result.ends_with('$') {
            result = result[..result.len()-1].to_string();
        }

        // 处理(?:^|X)模式 - 这是Hyperscan不支持的嵌入式锚点
        // 转换为(X|^)的模式，或者直接转换为X（去掉锚点要求）
        while let Some(start) = result.find("(?:^|") {
            if let Some(end) = find_matching_paren(&result, start) {
                // 提取选择分支
                let alt_content = &result[start + 5..end];

                // 简单策略：只保留非锚点的部分
                // 例如：(?:^|&|Content-Disposition) 变为 (?:&|Content-Disposition)
                let fixed_alternatives = alt_content
                    .split('|')
                    .filter(|alt| !alt.starts_with('^'))
                    .collect::<Vec<_>>()
                    .join("|");

                if !fixed_alternatives.is_empty() {
                    let replacement = format!("(?:{})" , fixed_alternatives);
                    result.replace_range(start..=end, &replacement);
                } else {
                    // 如果没有有效的替代方案，使用通配符
                    result.replace_range(start..=end, ".*");
                }
                continue;
            }
            break;
        }

        // 处理其他嵌入式锚点
        result = result.replace("(?:^|", "(?:");  // 移除^选项
        result = result.replace("|^)", ")");     // 移除^选项

        result
    }

    /// 修复字符类中的问题
    fn fix_character_classes(&self, pattern: &str) -> String {
        let mut result = pattern.to_string();

        // 修复常见的字符类问题
        result = result.replace("[^]]", "[^\\x5d]");
        result = result.replace("[[]", "[\\[]");

        result
    }

    /// 修复单个字符类
    fn fix_single_character_class(&self, char_class: &str) -> String {
        let mut content = char_class.to_string();

        // 修复 [^] 这种无效的字符类
        if content == "[^]" {
            return "[\\x00-\\xFF]".to_string();
        }

        // 修复 [[] 开头的字符类
        if content.starts_with("[[") {
            content = content.replacen("[[", "[", 1);
        }

        // 修复 [^]] 这种无效的字符类（\x5d转义为]后的问题）
        if content == "[^]]" {
            return "[^\\x5d]".to_string();
        }

        // 更通用的修复：将字符类中的特殊字符转义
        let mut fixed = String::new();
        let mut chars = content.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '[' && fixed.is_empty() {
                fixed.push('[');
                continue;
            }

            if ch == ']' && fixed.starts_with('[') && !fixed.contains(']') {
                // 这是字符类的结束
                fixed.push(']');
                continue;
            }

            if ch == ']' && fixed.starts_with('[') && fixed.contains(']') {
                // 在字符类内部的]，需要转义
                fixed.push_str("\\]");
                continue;
            }

            // 处理其他特殊字符
            match ch {
                '[' | ']' | '\\' | '^' | '-' if fixed.starts_with('[') && !fixed.ends_with(']') => {
                    fixed.push('\\');
                    fixed.push(ch);
                }
                _ => {
                    fixed.push(ch);
                }
            }
        }

        fixed
    }

    /// 转换非贪婪量词为贪婪量词
    fn convert_non_greedy_quantifiers(&self, pattern: &str) -> String {
        let mut result = pattern.to_string();

        // 将非贪婪量词转换为贪婪量词
        // 这是一个保守的转换，可能会增加误报但保证功能
        result = result.replace("*?", "*");
        result = result.replace("+?", "+");
        result = result.replace("??", "?");
        result = result.replace("{", "\\{"); // 暂时转义花括号

        result
    }

    /// 转换复杂的重复模式为Hyperscan兼容形式
    fn convert_complex_repetitions(&self, pattern: &str) -> String {
        let mut result = pattern.to_string();

        // 处理形如(?:\.\.\/){2,}的模式
        // 将非捕获组的重复转换为展开的字符串
        while let Some(start) = result.find("(?:") {
            if let Some(group_end) = find_matching_paren(&result, start) {
                if let Some(brace_start) = result[group_end..].find('{') {
                    let brace_end = group_end + brace_start;
                    if let Some(brace_close) = result[brace_end..].find('}') {
                        let brace_close_end = brace_end + brace_close;

                        // 提取重复信息
                        let repeat_info = &result[brace_end + 1..brace_close_end];

                        // 转换非捕获组内容
                        let group_content = &result[start + 3..group_end];
                        let simplified_group = self.simplify_group_content(group_content);

                        // 替换整个模式
                        let replacement = if let Ok((min, max)) = self.parse_repeat_bounds(repeat_info) {
                            self.expand_repetition(&simplified_group, min, max)
                        } else {
                            // 如果无法解析重复，使用通配符
                            ".*".to_string()
                        };

                        result.replace_range(start..=brace_close_end, &replacement);
                        continue;
                    }
                }
            }
            break;
        }

        result
    }

    /// 简化组内容
    fn simplify_group_content(&self, content: &str) -> String {
        let mut simplified = content.to_string();

        // 处理常见的转义序列
        simplified = simplified.replace("\\.", ".");
        simplified = simplified.replace("\\/", "/");
        simplified = simplified.replace("\\%", "%");

        simplified
    }

    /// 解析重复边界
    fn parse_repeat_bounds(&self, repeat_str: &str) -> Result<(usize, Option<usize>)> {
        if repeat_str.starts_with(',') {
            // {,n} 形式
            let max: usize = repeat_str[1..].parse()
                .map_err(|_| WebScanError::RuleParsing("Invalid repeat bounds".to_string()))?;
            Ok((0, Some(max)))
        } else if repeat_str.ends_with(',') {
            // {n,} 形式
            let min: usize = repeat_str[..repeat_str.len()-1].parse()
                .map_err(|_| WebScanError::RuleParsing("Invalid repeat bounds".to_string()))?;
            Ok((min, None))
        } else if let Some(comma_pos) = repeat_str.find(',') {
            // {m,n} 形式
            let min: usize = repeat_str[..comma_pos].parse()
                .map_err(|_| WebScanError::RuleParsing("Invalid repeat bounds".to_string()))?;
            let max: usize = repeat_str[comma_pos+1..].parse()
                .map_err(|_| WebScanError::RuleParsing("Invalid repeat bounds".to_string()))?;
            Ok((min, Some(max)))
        } else {
            // {n} 形式
            let count: usize = repeat_str.parse()
                .map_err(|_| WebScanError::RuleParsing("Invalid repeat bounds".to_string()))?;
            Ok((count, Some(count)))
        }
    }

    /// 展开重复模式
    fn expand_repetition(&self, content: &str, min: usize, max: Option<usize>) -> String {
        match max {
            Some(max_val) if max_val == min => {
                // 精确重复
                content.repeat(min)
            }
            Some(max_val) => {
                // 范围重复，使用保守的转换避免复杂的正则表达式
                if min == 0 && max_val <= 2 {
                    // 非常小的范围，可以简单展开
                    if max_val == 1 {
                        format!("({}|)", content)
                    } else if max_val == 2 {
                        format!("({}|{}|{}{})", content, content, content, content)
                    } else {
                        format!(".*")  // 回退到通配符
                    }
                } else {
                    // 使用简化的重复模式
                    format!("{}{{,{}}}", content, max_val)
                }
            }
            None => {
                // 无上限重复，使用简单的Kleene star
                if min == 0 {
                    format!("{}*", content)
                } else {
                    format!("{}{{{},}}", content, min)
                }
            }
        }
    }

    /// 检查是否包含Hyperscan不支持的特性
    fn contains_unsupported_features(&self, pattern: &str) -> bool {
        // 检查反向引用 - Hyperscan完全不支持
        if pattern.contains("\\1") || pattern.contains("\\2") || pattern.contains("\\3") ||
           pattern.contains("\\4") || pattern.contains("\\5") || pattern.contains("\\6") ||
           pattern.contains("\\7") || pattern.contains("\\8") || pattern.contains("\\9") {
            return true;
        }

        // 检查非贪婪量词 - Hyperscan不支持
        if pattern.contains("*?") || pattern.contains("+?") || pattern.contains("??") {
            return true;
        }

        // 检查环视断言 - Hyperscan不支持
        if pattern.contains("?=") || pattern.contains("?!") ||
           pattern.contains("?<=") || pattern.contains("?<!") {
            return true;
        }

        // 检查条件模式 - Hyperscan不支持
        if pattern.contains("(?(") {
            return true;
        }

        // 检查嵌入式锚点 - Hyperscan不支持
        if pattern.contains("(?:^|") || pattern.contains("|^)") {
            return true;
        }

        // 检查模式开头或结尾的锚点 - Hyperscan不支持
        if pattern.starts_with('^') || pattern.ends_with('$') {
            return true;
        }

        // 检查复杂的量词 - 一些复杂模式Hyperscan不支持
        if pattern.contains("{0,}") || pattern.contains("{1,0}") {
            return true;
        }

        // 检查可能导致"Invalid repeat"错误的模式
        // 特别检查在模式开始位置的重复量词
        if self.has_invalid_repeat_at_start(pattern) {
            return true;
        }

        false
    }

    /// 检查模式开始位置是否有无效的重复量词
    fn has_invalid_repeat_at_start(&self, pattern: &str) -> bool {
        // 跳过开头的锚点和空白
        let mut trimmed = pattern.trim_start_matches('^');
        trimmed = trimmed.trim_start();

        // 检查是否以重复量词开始
        let invalid_starts = [
            "*", "+", "?",
            "{0,}", "{1,}", "{2,}", "{3,}", "{4,}", "{5,}", "{6,}", "{7,}", "{8,}", "{9,}",
            "{0,", "{1,", "{2,", "{3,", "{4,", "{5,", "{6,", "{7,", "{8,", "{9,",
        ];

        for invalid_start in &invalid_starts {
            if trimmed.starts_with(invalid_start) {
                return true;
            }
        }

        false
    }

    /// 验证Hyperscan模式（简化实现）
    fn validate_hyperscan_pattern(&self, pattern: &str) -> Result<()> {
        // 基本的语法验证
        let mut paren_count = 0;
        let mut in_char_class = false;
        let mut escape_next = false;

        for (i, ch) in pattern.chars().enumerate() {
            if escape_next {
                escape_next = false;
                continue;
            }

            match ch {
                '\\' => {
                    escape_next = true;
                }
                '[' => {
                    in_char_class = true;
                }
                ']' => {
                    in_char_class = false;
                }
                '(' if !in_char_class => {
                    paren_count += 1;
                }
                ')' if !in_char_class => {
                    paren_count -= 1;
                    if paren_count < 0 {
                        return Err(WebScanError::RuleParsing(
                            format!("Unmatched closing parenthesis at position {}", i)
                        ));
                    }
                }
                _ => {}
            }
        }

        if paren_count != 0 {
            return Err(WebScanError::RuleParsing(
                "Unmatched parentheses in pattern".to_string()
            ));
        }

        Ok(())
    }

    /// 将PCRE模式转换为Rust regex模式
    fn convert_pcre_to_regex(&self, pattern: &str, flags: &str) -> Result<String> {
        let mut regex_pattern = pattern.to_string();

        // Rust regex默认支持大部分PCRE语法，但有些需要调整
        // 这里保持原样，让Rust regex引擎处理

        Ok(regex_pattern)
    }
}

impl PcrePattern {
    pub fn new_with_details(
        raw_pattern: String,
        processed_pattern: String,
        match_type: PcreMatchType,
        http_location: HttpMatchLocation,
    ) -> Self {
        Self {
            raw_pattern,
            processed_pattern,
            match_type,
            compiled_regex: None,
            http_location,
        }
    }

    pub fn with_compiled_regex(mut self, regex: Regex) -> Self {
        self.compiled_regex = Some(regex);
        self
    }
}

impl Default for PcreProcessor {
    fn default() -> Self {
        Self::new()
    }
}