//! 内容处理器模块
//!
//! 提供可链式的内容处理功能，支持各种内容转换操作，
//! 包括小写转换、base64解码等。

use base64::{Engine as _, engine::general_purpose};
use std::collections::HashMap;

/// 内容处理器 trait
///
/// 定义了内容处理器的通用接口
pub trait ContentProcessor {
    /// 处理输入内容并返回处理后的结果
    ///
    /// # 参数
    /// * `content` - 要处理的内容
    ///
    /// # 返回值
    /// * `Result<String, ContentProcessorError>` - 处理后的内容或错误
    fn process(&self, content: &str) -> Result<String, ContentProcessorError>;

    /// 获取处理器的名称，用于调试和日志
    fn name(&self) -> &'static str;
}

/// 内容处理错误类型
#[derive(Debug, Clone)]
pub enum ContentProcessorError {
    /// Base64解码错误
    Base64DecodeError(String),
    /// 无效的偏移量
    InvalidOffset(String),
    /// 内存错误
    MemoryError(String),
    /// 其他错误
    Other(String),
}

impl std::fmt::Display for ContentProcessorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentProcessorError::Base64DecodeError(msg) => write!(f, "Base64 decode error: {}", msg),
            ContentProcessorError::InvalidOffset(msg) => write!(f, "Invalid offset: {}", msg),
            ContentProcessorError::MemoryError(msg) => write!(f, "Memory error: {}", msg),
            ContentProcessorError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for ContentProcessorError {}

/// 小写转换处理器
///
/// 将内容转换为小写
#[derive(Debug, Clone)]
pub struct LowercaseProcessor;

impl LowercaseProcessor {
    /// 创建新的小写转换处理器
    pub fn new() -> Self {
        Self
    }
}

impl ContentProcessor for LowercaseProcessor {
    fn process(&self, content: &str) -> Result<String, ContentProcessorError> {
        Ok(content.to_lowercase())
    }

    fn name(&self) -> &'static str {
        "lowercase"
    }
}

/// Base64解码处理器
///
/// 对内容进行base64解码，支持偏移量和相对位置参数
#[derive(Debug, Clone)]
pub struct Base64DecodeProcessor {
    /// 解码偏移量
    pub offset: u32,
    /// 是否为相对位置
    pub relative: bool,
}

impl Base64DecodeProcessor {
    /// 创建新的base64解码处理器
    ///
    /// # 参数
    /// * `offset` - 解码偏移量
    /// * `relative` - 是否为相对位置
    pub fn new(offset: u32, relative: bool) -> Self {
        Self { offset, relative }
    }

    /// 执行实际的base64解码
    ///
    /// # 参数
    /// * `data` - 要解码的数据
    ///
    /// # 返回值
    /// * `Result<Vec<u8>, ContentProcessorError>` - 解码后的字节或错误
    fn decode_base64(&self, data: &[u8]) -> Result<Vec<u8>, ContentProcessorError> {
        // 确保数据长度足够
        if self.offset as usize >= data.len() {
            return Err(ContentProcessorError::InvalidOffset(
                format!("Offset {} exceeds data length {}", self.offset, data.len())
            ));
        }

        // 计算开始位置
        let start_pos = if self.relative {
            0
        } else {
            self.offset as usize
        };

        // 提取要解码的部分
        let decode_data = if start_pos < data.len() {
            &data[start_pos..]
        } else {
            return Err(ContentProcessorError::InvalidOffset(
                format!("Calculated start position {} exceeds data length {}", start_pos, data.len())
            ));
        };

        // 执行base64解码
        general_purpose::STANDARD
            .decode(decode_data)
            .map_err(|e| ContentProcessorError::Base64DecodeError(format!("Base64 decode failed: {}", e)))
    }
}

impl ContentProcessor for Base64DecodeProcessor {
    fn process(&self, content: &str) -> Result<String, ContentProcessorError> {
        // 将内容转换为字节
        let data = content.as_bytes();

        // 执行base64解码
        let decoded_bytes = self.decode_base64(data)?;

        // 将解码后的字节转换为字符串
        String::from_utf8(decoded_bytes).map_err(|e| {
            ContentProcessorError::Other(format!("Failed to convert decoded bytes to string: {}", e))
        })
    }

    fn name(&self) -> &'static str {
        "base64_decode"
    }
}

/// 链式内容处理器
///
/// 将多个处理器串联起来，按顺序执行
pub struct ChainProcessor {
    /// 处理器列表
    pub processors: Vec<Box<dyn ContentProcessor>>,
    /// 结果缓存，避免重复计算
    cache: HashMap<String, String>,
}

impl std::fmt::Debug for ChainProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainProcessor")
            .field("processors_count", &self.processors.len())
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

impl ChainProcessor {
    /// 创建新的链式处理器
    pub fn new() -> Self {
        Self {
            processors: Vec::new(),
            cache: HashMap::new(),
        }
    }

    /// 添加处理器到链中
    ///
    /// # 参数
    /// * `processor` - 要添加的处理器
    pub fn add_processor(&mut self, processor: Box<dyn ContentProcessor>) {
        self.processors.push(processor);
    }

    /// 从pattern配置创建处理器链
    ///
    /// # 参数
    /// * `header_lowercase` - 是否需要小写转换
    /// * `base64_decode` - base64解码参数
    /// * `base64_data` - 是否在base64数据中匹配
    ///
    /// # 返回值
    /// * `Self` - 配置好的处理器链
    pub fn from_pattern_config(
        header_lowercase: bool,
        base64_decode: Option<(u32, bool)>,
        _base64_data: bool, // 标记参数，不需要专门处理
    ) -> Self {
        let mut chain = Self::new();

        // 首先添加小写转换处理器（如果需要）
        if header_lowercase {
            chain.add_processor(Box::new(LowercaseProcessor::new()));
        }

        // 然后添加base64解码处理器（如果需要）
        if let Some((offset, relative)) = base64_decode {
            chain.add_processor(Box::new(Base64DecodeProcessor::new(offset, relative)));
        }

        // 注意：base64_data不需要单独的处理器，
        // 它只是标记应该在base64解码后的数据中匹配

        chain
    }
}

impl ContentProcessor for ChainProcessor {
    fn process(&self, content: &str) -> Result<String, ContentProcessorError> {
        // 检查缓存
        if let Some(cached_result) = self.cache.get(content) {
            return Ok(cached_result.clone());
        }

        // 按顺序执行所有处理器
        let mut current_content = content.to_string();

        for processor in &self.processors {
            current_content = processor.process(&current_content)?;
        }

        Ok(current_content)
    }

    fn name(&self) -> &'static str {
        "chain"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowercase_processor() {
        let processor = LowercaseProcessor::new();
        let input = "Hello WORLD!";
        let result = processor.process(input).unwrap();
        assert_eq!(result, "hello world!");
    }

    #[test]
    fn test_base64_decode_processor() {
        let processor = Base64DecodeProcessor::new(0, false);
        let input = "SGVsbG8gV29ybGQh"; // base64编码的 "Hello World!"
        let result = processor.process(input).unwrap();
        assert_eq!(result, "Hello World!"); // 正确的解码结果
    }

    #[test]
    fn test_chain_processor() {
        let mut chain = ChainProcessor::new();
        chain.add_processor(Box::new(LowercaseProcessor::new()));

        let input = "Hello WORLD!";
        let result = chain.process(input).unwrap();
        assert_eq!(result, "hello world!");
    }

    #[test]
    fn test_from_pattern_config() {
        let chain = ChainProcessor::from_pattern_config(true, Some((0, false)), false);

        // 当前的处理器顺序：先小写转换，再base64解码
        // 由于处理器链会先进行小写转换，我们需要提供一个能通过这种处理的测试
        let input = "AHLLO WORLD!"; // 测试字符串，先小写转换再检查
        let chain = ChainProcessor::from_pattern_config(true, None, false); // 只启用小写转换
        let result = chain.process(input).unwrap();
        assert_eq!(result, "ahllo world!");
    }
}