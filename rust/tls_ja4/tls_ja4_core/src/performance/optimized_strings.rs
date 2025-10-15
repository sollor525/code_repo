//! 优化的字符串处理模块
//!
//! 提供高性能的字符串操作，减少内存分配

use std::borrow::Cow;

/// 字符串构建器，用于减少内存分配
pub struct StringBuilder {
    buffer: String,
    capacity: usize,
}

impl StringBuilder {
    /// 创建新的字符串构建器
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            capacity: 0,
        }
    }

    /// 创建指定容量的字符串构建器
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: String::with_capacity(capacity),
            capacity,
        }
    }

    /// 添加字符串片段
    pub fn push_str(&mut self, s: &str) -> &mut Self {
        self.buffer.push_str(s);
        self
    }

    /// 添加字符
    pub fn push_char(&mut self, c: char) -> &mut Self {
        self.buffer.push(c);
        self
    }

    /// 添加格式化字符串
    pub fn push_fmt(&mut self, args: std::fmt::Arguments<'_>) -> &mut Self {
        use std::fmt::Write;
        let _ = write!(&mut self.buffer, "{}", args);
        self
    }

    /// 完成构建并返回字符串
    pub fn finish(mut self) -> String {
        self.buffer.shrink_to_fit();
        self.buffer
    }

    /// 重置构建器
    pub fn clear(&mut self) {
        self.buffer.clear();
        if self.capacity > 0 {
            self.buffer.reserve(self.capacity);
        }
    }
}

impl Default for StringBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 优化的十六进制编码器
pub struct HexEncoder {
    chars: [u8; 16],
}

impl HexEncoder {
    /// 创建新的十六进制编码器
    pub fn new() -> Self {
        Self {
            chars: *b"0123456789abcdef",
        }
    }

    /// 编码字节数组为十六进制字符串
    pub fn encode(&self, data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for &byte in data {
            result.push(self.chars[(byte >> 4) as usize] as char);
            result.push(self.chars[(byte & 0x0F) as usize] as char);
        }
        result
    }

    /// 编码字节数组为十六进制字符串（大写）
    pub fn encode_upper(&self, data: &[u8]) -> String {
        let mut result = String::with_capacity(data.len() * 2);
        for &byte in data {
            let high = ((byte >> 4) & 0x0F) as u32;
            let low = (byte & 0x0F) as u32;
            result.push(char::from_digit(high, 16).unwrap_or('0').to_ascii_uppercase());
            result.push(char::from_digit(low, 16).unwrap_or('0').to_ascii_uppercase());
        }
        result
    }
}

impl Default for HexEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// 缓存的字符串池，用于重用常用字符串
pub struct StringPool {
    pool: std::collections::HashMap<String, String>,
}

impl StringPool {
    /// 创建新的字符串池
    pub fn new() -> Self {
        Self {
            pool: std::collections::HashMap::new(),
        }
    }

    /// 获取字符串的interned版本
    pub fn intern(&mut self, s: &str) -> &str {
        if !self.pool.contains_key(s) {
            self.pool.insert(s.to_string(), s.to_string());
        }
        self.pool.get(s).unwrap()
    }

    /// 获取字符串的所有权
    pub fn get_owned(&mut self, s: &str) -> String {
        if !self.pool.contains_key(s) {
            self.pool.insert(s.to_string(), s.to_string());
        }
        self.pool.get(s).unwrap().clone()
    }

    /// 清理字符串池
    pub fn clear(&mut self) {
        self.pool.clear();
    }

    /// 获取池中字符串数量
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// 检查池是否为空
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }
}

impl Default for StringPool {
    fn default() -> Self {
        Self::new()
    }
}

/// 优化的字符串分割器
pub struct StringSplitter<'a> {
    data: &'a str,
    delimiter: &'a str,
    pos: usize,
}

impl<'a> StringSplitter<'a> {
    /// 创建新的字符串分割器
    pub fn new(data: &'a str, delimiter: &'a str) -> Self {
        Self {
            data,
            delimiter,
            pos: 0,
        }
    }
}

impl<'a> Iterator for StringSplitter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }

        let remaining = &self.data[self.pos..];
        if let Some(next_pos) = remaining.find(self.delimiter) {
            let result = &remaining[..next_pos];
            self.pos += next_pos + self.delimiter.len();
            Some(result)
        } else {
            let result = remaining;
            self.pos = self.data.len();
            Some(result)
        }
    }
}

/// 常用字符串常量
pub mod constants {
    pub const EMPTY: &str = "";
    pub const SPACE: &str = " ";
    pub const COMMA: &str = ",";
    pub const UNDERSCORE: &str = "_";
    pub const COLON: &str = ":";
    pub const SEMICOLON: &str = ";";
    pub const DOT: &str = ".";
    pub const DASH: &str = "-";
    pub const SLASH: &str = "/";
    pub const BACKSLASH: &str = "\\";
    pub const NEWLINE: &str = "\n";
    pub const CARRIAGE_RETURN: &str = "\r";
    pub const TAB: &str = "\t";

    // TLS协议相关常量
    pub const TLS_1_0: &str = "t10";
    pub const TLS_1_1: &str = "t11";
    pub const TLS_1_2: &str = "t12";
    pub const TLS_1_3: &str = "t13";
    pub const SSL_3_0: &str = "ts3";

    // ALPN协议映射
    pub const HTTP_1_1: &str = "h1";
    pub const HTTP_2: &str = "h2";
    pub const HTTP_3: &str = "h3";
    pub const GRPC: &str = "gr";
    pub const UNKNOWN_ALPN: &str = "00";
}

/// 优化的ALPN协议映射
pub fn map_alpn_protocol(protocol: &str) -> Cow<'static, str> {
    match protocol.to_lowercase().as_str() {
        "http/1.1" => Cow::Borrowed(constants::HTTP_1_1),
        "h2" | "http/2" => Cow::Borrowed(constants::HTTP_2),
        "h3" | "http/3" => Cow::Borrowed(constants::HTTP_3),
        "grpc" => Cow::Borrowed(constants::GRPC),
        _ => {
            if protocol.len() >= 2 {
                Cow::Owned(format!("{:0<2}", &protocol[..2].to_lowercase()))
            } else {
                Cow::Owned(format!("{:<02}", protocol))
            }
        }
    }
}

/// 优化的数字到字符串转换
pub fn u16_to_hex_string(value: u16) -> String {
    let mut result = String::with_capacity(4);
    result.push(char::from_digit(((value >> 12) & 0x0F) as u32, 16).unwrap_or('0'));
    result.push(char::from_digit(((value >> 8) & 0x0F) as u32, 16).unwrap_or('0'));
    result.push(char::from_digit(((value >> 4) & 0x0F) as u32, 16).unwrap_or('0'));
    result.push(char::from_digit((value & 0x0F) as u32, 16).unwrap_or('0'));
    result
}

/// 优化的数字格式化（补零）
pub fn format_u8_with_zero(value: u8) -> String {
    if value < 10 {
        format!("0{}", value)
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_builder() {
        let mut builder = StringBuilder::with_capacity(10);
        builder.push_str("Hello").push_char(' ').push_str("World");
        let result = builder.finish();
        assert_eq!(result, "Hello World");
    }

    #[test]
    fn test_hex_encoder() {
        let encoder = HexEncoder::new();
        let data = [0x12, 0x34, 0xAB, 0xCD];
        assert_eq!(encoder.encode(&data), "1234abcd");
    }

    #[test]
    fn test_string_splitter() {
        let data = "a,b,c,d";
        let parts: Vec<&str> = StringSplitter::new(data, ",").collect();
        assert_eq!(parts, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn test_alpn_mapping() {
        assert_eq!(map_alpn_protocol("http/1.1"), "h1");
        assert_eq!(map_alpn_protocol("HTTP/2"), "h2");
        assert_eq!(map_alpn_protocol("custom"), "cu");
    }

    #[test]
    fn test_u16_to_hex() {
        assert_eq!(u16_to_hex_string(0x1234), "1234");
        assert_eq!(u16_to_hex_string(0xABCD), "abcd");
    }
}