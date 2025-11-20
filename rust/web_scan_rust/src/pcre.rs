//! PCRE（Perl Compatible Regular Expressions）处理模块 - 简化版本
//!
//! 临时简化实现，用于避免cbindgen编译问题
//! 完整实现将在单独的文件中保留

// 重新导出基本类型以保持API兼容性
pub use regex::Regex;

/// 简化的PCRE匹配类型
#[derive(Debug, Clone, PartialEq)]
pub enum PcreMatchType {
    Hyperscan,
    ConvertedHyperscan,
    RegexFallback,
}

/// 简化的PCRE模式
#[derive(Debug, Clone)]
pub struct PcrePattern {
    pub raw_pattern: String,
    pub processed_pattern: String,
    pub match_type: PcreMatchType,
    pub compiled_regex: Option<Regex>,
    pub http_location: crate::rules::HttpMatchLocation,
}

impl PcrePattern {
    pub fn new(pattern: &str) -> Self {
        Self {
            raw_pattern: pattern.to_string(),
            processed_pattern: pattern.to_string(),
            match_type: PcreMatchType::RegexFallback,
            compiled_regex: Regex::new(pattern).ok(),
            http_location: crate::rules::HttpMatchLocation::Any,
        }
    }

    /// 创建带有完整控制的PCRE模式
    pub fn new_with_details(raw_pattern: String, processed_pattern: String, http_location: crate::rules::HttpMatchLocation) -> Self {
        let compiled_regex = Regex::new(&processed_pattern).ok();
        Self {
            raw_pattern,
            processed_pattern,
            match_type: PcreMatchType::RegexFallback,
            compiled_regex,
            http_location,
        }
    }
}

/// 简化的PCRE处理器
pub struct PcreProcessor {
    // 简化实现
}

impl PcreProcessor {
    pub fn new() -> Self {
        Self {}
    }

    pub fn process_pcre_pattern(
        &mut self,
        pcre_str: &str,
        _http_location: crate::rules::HttpMatchLocation,
        _startswith: bool,
        _endswith: bool,
        _distance: Option<u32>,
        _depth: Option<u32>,
        _offset: Option<u32>,
        _within: Option<u32>,
    ) -> crate::error::Result<PcrePattern> {
        // 改进的PCRE解析逻辑
        let trimmed = pcre_str.trim_matches('"');
        let (pattern, raw_pattern) = if trimmed.starts_with('/') && trimmed.len() > 1 {
            // 标准格式：/pattern/ 或 /pattern/flags
            let pcre_without_first_slash = &trimmed[1..];

            if let Some(flags_pos) = pcre_without_first_slash.rfind('/') {
                // 找到标志分隔符，检查标志部分是否只包含有效标志
                let pattern_part = &pcre_without_first_slash[..flags_pos];
                let flags_part = &pcre_without_first_slash[flags_pos + 1..];

                // 如果标志部分只包含已知标志且不为空，则pattern_part是模式，flags_part是标志
                // 否则，斜杠可能是模式的一部分
                let valid_flags = !flags_part.is_empty() && flags_part.chars().all(|c| "imsx".contains(c));

                if valid_flags {
                    // 有有效的标志，pattern_part是模式
                    (pattern_part.to_string(), pattern_part.to_string())
                } else {
                    // 标志无效，可能整个字符串都是模式（包括斜杠）
                    (pcre_without_first_slash.to_string(), pcre_without_first_slash.to_string())
                }
            } else {
                // 没有找到结束斜杠，整个内容都是模式（带开头斜杠）
                (trimmed.to_string(), trimmed.to_string())
            }
        } else {
            // 简化格式：直接使用字符串
            (trimmed.to_string(), trimmed.to_string())
        };

        Ok(PcrePattern::new_with_details(raw_pattern, pattern, _http_location))
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
    fn test_pcre_pattern_creation() {
        let pattern = PcrePattern::new("test.*pattern");
        assert_eq!(pattern.raw_pattern, "test.*pattern");
        assert_eq!(pattern.processed_pattern, "test.*pattern");
        assert_eq!(pattern.match_type, PcreMatchType::RegexFallback);
        assert_eq!(pattern.http_location, crate::rules::HttpMatchLocation::Any);
    }

    #[test]
    fn test_pcre_processor() {
        let mut processor = PcreProcessor::new();

        let result = processor.process_pcre_pattern(
            "/test/i",
            crate::rules::HttpMatchLocation::Any,
            false,
            false,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_ok());
        let pcre_pattern = result.unwrap();
        assert_eq!(pcre_pattern.raw_pattern, "test");
        assert_eq!(pcre_pattern.match_type, PcreMatchType::RegexFallback);
    }

    #[test]
    fn test_pcre_regex_matching() {
        let pattern = PcrePattern::new("test.*pattern");

        if let Some(ref regex) = pattern.compiled_regex {
            assert!(regex.is_match("test123pattern"));
            assert!(regex.is_match("testpattern"));
            assert!(!regex.is_match("nomatch"));
        } else {
            panic!("Regex should be compiled");
        }
    }

    #[test]
    fn test_complex_regex() {
        let pattern = PcrePattern::new(r"\d{4}-\d{2}-\d{2}");

        if let Some(ref regex) = pattern.compiled_regex {
            assert!(regex.is_match("2023-12-25"));
            assert!(regex.is_match("1999-01-01"));
            assert!(!regex.is_match("invalid-date"));
            assert!(!regex.is_match("12-25-2023"));
        } else {
            panic!("Regex should be compiled");
        }
    }
}