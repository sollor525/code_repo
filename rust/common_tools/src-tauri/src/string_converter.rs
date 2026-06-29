use serde::{Deserialize, Serialize};

/// 字符串转换器，支持 \000 和 \u0000 格式之间的双向转换
#[derive(Debug, Clone)]
pub struct StringConverter {
    /// 缓存转换结果以提高性能
    cache: std::collections::HashMap<String, String>,
}

impl StringConverter {
    /// 创建新的字符串转换器实例
    pub fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
        }
    }

    /// 将 \000 格式转换为 \u0000 格式
    ///
    /// # 参数
    /// * `input` - 包含 \000 格式转义序列的字符串
    ///
    /// # 返回值
    /// 转换后的字符串，其中 \000 被替换为 \u0000
    ///
    /// # 示例
    /// ```
    /// let converter = StringConverter::new();
    /// let input = "4\\000\\000\\000\\n5.0.54\\000";
    /// let result = converter.octal_to_unicode(input);
    /// assert_eq!(result, "4\\u0000\\u0000\\u0000\\n5.0.54\\u0000");
    /// ```
    pub fn octal_to_unicode(&mut self, input: &str) -> String {
        // 检查缓存
        if let Some(cached) = self.cache.get(input) {
            return cached.clone();
        }

        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '\\' {
                // 检查是否是八进制转义序列 \000
                let mut octal_digits = String::new();
                let mut digit_count = 0;

                // 收集后续的数字字符（最多3位）
                while let Some(&next_ch) = chars.peek() {
                    if next_ch.is_ascii_digit() && digit_count < 3 {
                        octal_digits.push(chars.next().unwrap());
                        digit_count += 1;
                    } else {
                        break;
                    }
                }

                // 如果收集到了3位数字，认为是八进制转义序列
                if digit_count == 3 {
                    // 验证是否是有效的八进制数
                    if let Ok(octal_value) = u8::from_str_radix(&octal_digits, 8) {
                        // 转换为 Unicode 格式
                        result.push_str(&format!("\\u{:04x}", octal_value));
                        continue;
                    }
                }

                // 如果不是有效的八进制转义序列，保持原样
                result.push(ch);
                result.push_str(&octal_digits);
            } else {
                result.push(ch);
            }
        }

        // 缓存结果
        self.cache.insert(input.to_string(), result.clone());
        result
    }

    /// 将 \u0000 格式转换为 \000 格式
    ///
    /// # 参数
    /// * `input` - 包含 \u0000 格式转义序列的字符串
    ///
    /// # 返回值
    /// 转换后的字符串，其中 \u0000 被替换为 \000
    ///
    /// # 示例
    /// ```
    /// let converter = StringConverter::new();
    /// let input = "4\\u0000\\u0000\\u0000\\n5.0.54\\u0000";
    /// let result = converter.unicode_to_octal(input);
    /// assert_eq!(result, "4\\000\\000\\000\\n5.0.54\\000");
    /// ```
    pub fn unicode_to_octal(&mut self, input: &str) -> String {
        // 检查缓存
        if let Some(cached) = self.cache.get(&format!("reverse_{}", input)) {
            return cached.clone();
        }

        let mut result = String::new();
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '\\' {
                // 检查后续是否是 u
                if let Some('u') = chars.peek() {
                    chars.next(); // 消费 'u'

                    // 收集后续的十六进制数字（最多4位）
                    let mut hex_digits = String::new();
                    let mut digit_count = 0;

                    while let Some(&next_ch) = chars.peek() {
                        if (next_ch.is_ascii_hexdigit() || next_ch == 'x') && digit_count < 6 {
                            // 跳过可能的前缀 'x'
                            if next_ch == 'x' && hex_digits.is_empty() {
                                chars.next();
                                continue;
                            }
                            hex_digits.push(chars.next().unwrap());
                            digit_count += 1;
                        } else {
                            break;
                        }
                    }

                    // 如果收集到了4位十六进制数字，进行转换
                    if hex_digits.len() >= 4 {
                        // 尝试解析为十六进制数
                        if let Ok(unicode_value) = u32::from_str_radix(&hex_digits, 16) {
                            if unicode_value <= 0xFF {
                                // 对于 0-255 范围内的值，转换为八进制格式
                                let octal_value = format!("{:03o}", unicode_value);
                                result.push('\\');
                                result.push_str(&octal_value);
                                continue;
                            } else {
                                // 对于大于255的值，保持原格式
                                result.push_str("\\u");
                                result.push_str(&hex_digits);
                                continue;
                            }
                        }
                    }

                    // 如果解析失败，恢复原始格式
                    result.push_str("\\u");
                    result.push_str(&hex_digits);
                } else {
                    result.push(ch);
                }
            } else {
                result.push(ch);
            }
        }

        // 缓存结果
        self.cache.insert(format!("reverse_{}", input), result.clone());
        result
    }

    /// 自动检测输入格式并进行相应的转换
    ///
    /// # 参数
    /// * `input` - 输入字符串
    ///
    /// # 返回值
    /// 转换后的字符串
    pub fn auto_convert(&mut self, input: &str) -> Result<String, String> {
        // 检测输入格式
        if input.contains("\\u") {
            Ok(self.unicode_to_octal(input))
        } else if input.contains("\\000") || input.contains("\\001") || input.contains("\\002") ||
                  input.contains("\\003") || input.contains("\\004") || input.contains("\\005") ||
                  input.contains("\\006") || input.contains("\\007") || input.contains("\\010") ||
                  input.contains("\\011") || input.contains("\\012") || input.contains("\\013") ||
                  input.contains("\\014") || input.contains("\\015") || input.contains("\\016") ||
                  input.contains("\\017") || input.contains("\\020") || input.contains("\\021") ||
                  input.contains("\\022") || input.contains("\\023") || input.contains("\\024") ||
                  input.contains("\\025") || input.contains("\\026") || input.contains("\\027") ||
                  input.contains("\\030") || input.contains("\\031") || input.contains("\\032") ||
                  input.contains("\\033") || input.contains("\\034") || input.contains("\\035") ||
                  input.contains("\\036") || input.contains("\\037") || input.contains("\\040") ||
                  input.contains("\\041") || input.contains("\\042") || input.contains("\\043") ||
                  input.contains("\\044") || input.contains("\\045") || input.contains("\\046") ||
                  input.contains("\\047") || input.contains("\\050") || input.contains("\\051") ||
                  input.contains("\\052") || input.contains("\\053") || input.contains("\\054") ||
                  input.contains("\\055") || input.contains("\\056") || input.contains("\\057") ||
                  input.contains("\\060") || input.contains("\\061") || input.contains("\\062") ||
                  input.contains("\\063") || input.contains("\\064") || input.contains("\\065") ||
                  input.contains("\\066") || input.contains("\\067") || input.contains("\\070") ||
                  input.contains("\\071") || input.contains("\\072") || input.contains("\\073") ||
                  input.contains("\\074") || input.contains("\\075") || input.contains("\\076") ||
                  input.contains("\\077") {
            Ok(self.octal_to_unicode(input))
        } else {
            Err("无法检测到有效的转换格式".to_string())
        }
    }

    /// 清空缓存（仅用于测试，运行时每请求新建实例、缓存不跨请求）
    #[cfg(test)]
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// 获取缓存大小（仅用于测试）
    #[cfg(test)]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for StringConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// 字符串转换请求结构
#[derive(Debug, Deserialize)]
pub struct StringConvertRequest {
    /// 输入字符串
    pub input: String,
    /// 转换类型："octal_to_unicode", "unicode_to_octal", "auto"
    pub conversion_type: String,
}

/// 字符串转换响应结构
#[derive(Debug, Serialize)]
pub struct StringConvertResponse {
    /// 原始输入字符串
    pub input: String,
    /// 转换结果
    pub result: String,
    /// 转换类型
    pub conversion_type: String,
    /// 是否为自动检测
    pub auto_detected: bool,
    /// 字符串长度（转换前）
    pub original_length: usize,
    /// 字符串长度（转换后）
    pub converted_length: usize,
}

/// 处理字符串转换请求
pub fn process_string_conversion(request: StringConvertRequest) -> Result<StringConvertResponse, String> {
    let mut converter = StringConverter::new();
    let original_length = request.input.len();

    let (result, auto_detected) = match request.conversion_type.as_str() {
        "octal_to_unicode" => {
            (converter.octal_to_unicode(&request.input), false)
        },
        "unicode_to_octal" => {
            (converter.unicode_to_octal(&request.input), false)
        },
        "auto" => {
            match converter.auto_convert(&request.input) {
                Ok(converted) => (converted, true),
                Err(e) => return Err(e),
            }
        },
        _ => return Err("无效的转换类型".to_string()),
    };

    let converted_length = result.len();

    Ok(StringConvertResponse {
        input: request.input,
        result,
        conversion_type: request.conversion_type,
        auto_detected,
        original_length,
        converted_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_octal_to_unicode() {
        let mut converter = StringConverter::new();

        // 测试基本转换
        let input = "4\\000\\000\\000\\n5.0.54\\000";
        let expected = "4\\u0000\\u0000\\u0000\\n5.0.54\\u0000";
        assert_eq!(converter.octal_to_unicode(input), expected);

        // 测试复杂示例
        let complex_input = "4\\000\\000\\000\\n5.0.54\\000^\\000\\000\\000>~$4uth,\\000,\\242!\\002\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000>612IWZ>fhWX\\000";
        let result = converter.octal_to_unicode(complex_input);
        assert!(result.contains("\\u0000"));
        assert!(result.contains("\\u00a2"));
        assert!(result.contains("\\u0002"));
    }

    #[test]
    fn test_unicode_to_octal() {
        let mut converter = StringConverter::new();

        // 测试基本转换
        let input = "4\\u0000\\u0000\\u0000\\n5.0.54\\u0000";
        let expected = "4\\000\\000\\000\\n5.0.54\\000";
        assert_eq!(converter.unicode_to_octal(input), expected);

        // 测试复杂示例
        let complex_input = "4\\u0000\\u0000\\u0000\\n5.0.54\\u0000^\\u0000\\u0000\\u0000>~$4uth,\\u0000,\\u00a2!\\u0002\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000>612IWZ>fhWX\\u0000";
        let result = converter.unicode_to_octal(complex_input);
        assert!(result.contains("\\000"));
        assert!(result.contains("\\242"));
        assert!(result.contains("\\002"));
    }

    #[test]
    fn test_auto_convert() {
        let mut converter = StringConverter::new();

        // 测试八进制格式检测
        let octal_input = "test\\000\\001\\002";
        let result = converter.auto_convert(octal_input).unwrap();
        assert!(result.contains("\\u0000"));

        // 测试 Unicode 格式检测
        let unicode_input = "test\\u0000\\u0001\\u0002";
        let result = converter.auto_convert(unicode_input).unwrap();
        assert!(result.contains("\\000"));
    }

    #[test]
    fn test_round_trip_conversion() {
        let mut converter = StringConverter::new();

        let original = "4\\000\\000\\000\\n5.0.54\\000^\\000\\000\\000>~$4uth,\\000,\\242!\\002\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000>612IWZ>fhWX\\000";

        // 八进制 -> Unicode -> 八进制
        let unicode = converter.octal_to_unicode(original);
        let back_to_octal = converter.unicode_to_octal(&unicode);
        assert_eq!(original, back_to_octal);

        // Unicode -> 八进制 -> Unicode
        let back_to_unicode = converter.octal_to_unicode(&back_to_octal);
        assert_eq!(unicode, back_to_unicode);
    }

    #[test]
    fn test_edge_cases() {
        let mut converter = StringConverter::new();

        // 测试空字符串
        assert_eq!(converter.octal_to_unicode(""), "");
        assert_eq!(converter.unicode_to_octal(""), "");

        // 测试无转义序列的字符串
        assert_eq!(converter.octal_to_unicode("normal string"), "normal string");
        assert_eq!(converter.unicode_to_octal("normal string"), "normal string");

        // 测试无效的八进制序列
        assert_eq!(converter.octal_to_unicode("test\\999"), "test\\999");
        assert_eq!(converter.octal_to_unicode("test\\12"), "test\\12");

        // 测试无效的 Unicode 序列
        assert_eq!(converter.unicode_to_octal("test\\uZZZZ"), "test\\uZZZZ");
        assert_eq!(converter.unicode_to_octal("test\\u12"), "test\\u12");
    }

    #[test]
    fn test_cache_functionality() {
        let mut converter = StringConverter::new();

        // 初始缓存为空
        assert_eq!(converter.cache_size(), 0);

        // 执行转换应该填充缓存
        let input = "test\\000\\001";
        converter.octal_to_unicode(input);
        assert_eq!(converter.cache_size(), 1);

        // 再次执行相同转换应该使用缓存
        converter.octal_to_unicode(input);
        assert_eq!(converter.cache_size(), 1);

        // 清空缓存
        converter.clear_cache();
        assert_eq!(converter.cache_size(), 0);
    }
}