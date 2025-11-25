//! 协议检测模块
//! 
//! 从数据包载荷中快速准确地检测HTTP/HTTPS协议。
//! 这个模块负责分析网络数据包的内容，判断是否为Web流量。

// 导入错误处理相关类型
use crate::error::Result;
// 导入字符串处理模块
use std::str;

// 定义数据包流向枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum PacketDirection {
    Unknown = 0,   // 未知流向
    ToServer = 1,  // 客户端到服务器的请求包
    ToClient = 2,  // 服务器到客户端的响应包
}

// 定义协议类型枚举
// #[derive(...)] 自动实现指定的trait
// Debug: 允许使用{:?}格式化输出
// Clone: 允许复制值
// Copy: 允许按位复制（更轻量的Clone）
// PartialEq, Eq: 允许比较相等性
// #[repr(C)] 确保内存布局与C语言兼容
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub enum Protocol {
    Unknown = 0,  // 未知协议
    Http = 1,     // HTTP协议
    Https = 2,    // HTTPS协议（TLS加密的HTTP）
    Http2 = 3,    // HTTP/2协议
}

// 协议检测结果结构体
#[derive(Debug, Clone, Copy)]
#[repr(C)]  // C兼容的内存布局
pub struct ProtocolResult {
    pub protocol: Protocol,        // 检测到的协议类型
    pub confidence: u8,            // 置信度，范围0-100
    pub direction: PacketDirection, // 数据包流向
    pub status_code: Option<u16>,   // HTTP状态码（仅响应包）
}

// 协议检测器结构体
pub struct ProtocolDetector {
    // 预编译的模式，用于快速检测
    // &'static 表示静态生命周期，数据在程序整个运行期间都有效
    // [&'static str] 是字符串切片的数组
    http_methods: &'static [&'static str],   // HTTP方法列表
    http_versions: &'static [&'static str],  // HTTP版本列表
}

// 为ProtocolDetector实现Default trait
// 这允许使用ProtocolDetector::default()创建默认实例
impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new()  // 调用new()方法
    }
}

// 为ProtocolDetector实现方法
impl ProtocolDetector {
    /// 创建新的协议检测器实例
    /// 
    /// 这个构造函数初始化HTTP方法和版本的静态数组，
    /// 这些数据将用于快速模式匹配。
    pub fn new() -> Self {
        Self {
            // 常见的HTTP方法
            http_methods: &[
                "GET", "POST", "PUT", "DELETE", "HEAD", 
                "OPTIONS", "PATCH", "TRACE", "CONNECT"
            ],
            // 支持的HTTP版本
            http_versions: &["HTTP/1.0", "HTTP/1.1", "HTTP/2"],
        }
    }

    /// 从载荷中高性能地检测协议
    ///
    /// # 参数
    /// * `payload` - 要分析的数据包载荷（字节数组切片）
    ///
    /// # 返回值
    /// * `Result<ProtocolResult>` - 包含协议类型、置信度、流向和状态码的结果
    pub fn detect(&self, payload: &[u8]) -> Result<ProtocolResult> {
        // 检查载荷是否为空
        if payload.is_empty() {
            // Ok()包装成功的结果，这是Result类型的成功变体
            return Ok(ProtocolResult {
                protocol: Protocol::Unknown,
                confidence: 0,
                direction: PacketDirection::Unknown,
                status_code: None,
            });
        }

        // 快速路径：检查HTTP/2魔术字符串
        // HTTP/2连接以特定的字符串开始
        if payload.len() >= 24 && payload.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
            return Ok(ProtocolResult {
                protocol: Protocol::Http2,
                confidence: 100,  // 100%置信度
                direction: PacketDirection::ToServer, // HTTP/2连接前言是请求包
                status_code: None,
            });
        }

        // 快速路径：检查TLS/SSL握手（HTTPS）
        if self.is_tls_handshake(payload) {
            return Ok(ProtocolResult {
                protocol: Protocol::Https,
                confidence: 90,   // 90%置信度
                direction: PacketDirection::ToServer, // TLS握手是客户端发起的
                status_code: None,
            });
        }

        // HTTP检测 - 包含流向和状态码分析
        if let Some((confidence, direction, status_code)) = self.detect_http_detailed(payload) {
            return Ok(ProtocolResult {
                protocol: Protocol::Http,
                confidence,
                direction,
                status_code,
            });
        }

        // 如果都不匹配，返回未知协议
        Ok(ProtocolResult {
            protocol: Protocol::Unknown,
            confidence: 0,
            direction: PacketDirection::Unknown,
            status_code: None,
        })
    }

    /// 快速HTTP检测（向后兼容）
    ///
    /// 这个私有方法分析载荷的第一行，寻找HTTP特征。
    /// 返回Option<u8>，Some(confidence)表示检测到HTTP，None表示未检测到。
    fn detect_http(&self, payload: &[u8]) -> Option<u8> {
        // 调用详细检测方法，只返回置信度部分
        self.detect_http_detailed(payload).map(|(conf, _, _)| conf)
    }

    /// 详细HTTP检测（包含流向和状态码）
    ///
    /// 这个私有方法分析载荷的完整内容，识别HTTP协议、数据包流向和状态码。
    /// 返回Option<(u8, PacketDirection, Option<u16>)>，包含置信度、流向和状态码。
    fn detect_http_detailed(&self, payload: &[u8]) -> Option<(u8, PacketDirection, Option<u16>)> {
        // 将字节转换为字符串进行解析（只需要第一行）
        // iter()创建迭代器，position()找到第一个匹配条件的位置
        // |&b| 是闭包语法，&b表示解引用字节
        // ?操作符是错误传播语法，如果None则直接返回None
        let first_line_end = payload.iter().position(|&b| b == b'\n')?;

        // 提取第一行，限制最大256字节以提高性能
        // &payload[..first_line_end.min(256)] 是切片语法
        // str::from_utf8()尝试将字节转换为UTF-8字符串
        // .ok()? 将Result转换为Option，如果是Err则返回None
        let first_line = str::from_utf8(&payload[..first_line_end.min(256)]).ok()?;

        // 初始化置信度计数器
        let mut confidence = 0u8;  // u8表示8位无符号整数

        // 检查是否为HTTP响应（以状态码开头）
        if let Some((direction, status_code)) = self.detect_http_response(first_line) {
            // HTTP响应的置信度计算
            confidence += 50;  // 状态码格式匹配，增加50分置信度

            // 检查响应是否有HTTP头部
            if payload.len() > first_line_end + 1 {
                let headers_part = &payload[first_line_end + 1..];
                if self.has_http_headers(headers_part) {
                    confidence += 30;  // 有HTTP头部，增加30分置信度
                }
            }

            if confidence >= 50 {
                return Some((confidence.min(100), direction, Some(status_code)));
            } else {
                return None;
            }
        }

        // 检查是否为HTTP请求（以HTTP方法开头）
        let mut direction = PacketDirection::Unknown;
        for &method in self.http_methods {
            if first_line.starts_with(method) {
                confidence += 40;  // HTTP方法匹配，增加40分置信度
                direction = PacketDirection::ToServer; // 请求包是客户端到服务器
                break;             // 找到一个就够了，跳出循环
            }
        }

        // 检查HTTP版本
        for &version in self.http_versions {
            if first_line.contains(version) {
                confidence += 35;  // HTTP版本匹配，增加35分置信度
                break;
            }
        }

        // 检查其他HTTP指示符
        if first_line.contains(" / ") || first_line.contains("://") {
            confidence += 10;  // 路径或URL格式，增加10分置信度
        }

        // 检查载荷中是否有常见的HTTP头部
        if payload.len() > first_line_end + 1 {
            // 获取头部部分（第一行之后的内容）
            let headers_part = &payload[first_line_end + 1..];
            if self.has_http_headers(headers_part) {
                confidence += 15;  // 有HTTP头部，增加15分置信度
            }
        }

        // 如果置信度达到50分以上，认为是HTTP
        if confidence >= 50 {
            // min(100)确保置信度不超过100
            Some((confidence.min(100), direction, None))
        } else {
            None  // 置信度不够，不是HTTP
        }
    }

    /// 检查是否为TLS握手
    /// 
    /// TLS握手有特定的格式，通过检查前几个字节可以快速识别。
    fn is_tls_handshake(&self, payload: &[u8]) -> bool {
        // TLS记录至少需要6个字节
        if payload.len() < 6 {
            return false;
        }

        // TLS记录头部格式：[content_type(1字节), version(2字节), length(2字节)]
        let content_type = payload[0];  // 第一个字节是内容类型
        
        // 从大端字节序读取版本号（网络字节序）
        // u16::from_be_bytes()将字节数组转换为16位整数
        let version = u16::from_be_bytes([payload[1], payload[2]]);
        
        // 检查TLS握手（内容类型22）和有效的TLS版本
        // matches!宏用于模式匹配，0x0301..=0x0304表示范围匹配
        // 0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2, 0x0304=TLS1.3
        content_type == 22 && matches!(version, 0x0301..=0x0304)
    }

    /// 检查是否包含HTTP头部
    ///
    /// 通过寻找常见的HTTP头部字段来确认这是HTTP流量。
    fn has_http_headers(&self, data: &[u8]) -> bool {
        // 尝试将字节数据转换为字符串
        let headers_str = match str::from_utf8(data) {
            Ok(s) => s,      // 转换成功
            Err(_) => return false,  // 转换失败，不是有效的UTF-8
        };

        // 常见的HTTP头部字段
        let common_headers = [
            "Host:", "User-Agent:", "Accept:", "Content-Type:",
            "Content-Length:", "Connection:", "Authorization:"
        ];

        // 检查是否包含任何常见头部
        // iter()创建迭代器，any()检查是否有任何元素满足条件
        common_headers.iter().any(|&header| {
            // lines()按行分割字符串，any()检查是否有任何行满足条件
            headers_str.lines().any(|line| {
                // trim_start()移除行首空白字符，starts_with()检查是否以指定字符串开始
                line.trim_start().starts_with(header)
            })
        })
    }

    /// 检查是否为HTTP响应并解析状态码
    ///
    /// 这个方法检测HTTP响应格式，例如"HTTP/1.1 200 OK"
    /// 返回Option<(PacketDirection, u16)>，包含流向和状态码
    fn detect_http_response(&self, first_line: &str) -> Option<(PacketDirection, u16)> {
        // 检查是否以HTTP/开头（HTTP响应格式）
        if first_line.starts_with("HTTP/") {
            // 解析状态码，格式通常为 "HTTP/1.1 200 OK"
            let parts: Vec<&str> = first_line.split_whitespace().collect();

            // 确保有足够的部分来解析状态码
            if parts.len() >= 2 {
                // 尝试解析状态码
                if let Ok(status_code) = parts[1].parse::<u16>() {
                    // 验证状态码是否在有效范围内（100-599）
                    if (100..=599).contains(&status_code) {
                        log::debug!("Detected HTTP response with status code: {}", status_code);
                        return Some((PacketDirection::ToClient, status_code));
                    }
                }
            }
        }

        None // 不是HTTP响应
    }
}

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    // 导入父模块的所有公共项
    use super::*;

    /// 测试HTTP检测功能
    #[test]
    fn test_http_detection() {
        // 创建协议检测器实例
        let detector = ProtocolDetector::new();

        // 模拟一个HTTP请求的字节数据
        // b"..." 语法创建字节字符串字面量
        let http_request = b"GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";

        // 调用检测方法，unwrap()用于获取Result中的Ok值
        // 如果是Err，unwrap()会导致panic，但在测试中这是可以接受的
        let result = detector.detect(http_request).unwrap();

        // assert_eq!宏用于断言两个值相等
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.direction, PacketDirection::ToServer); // 请求包
        assert_eq!(result.status_code, None); // 请求包没有状态码
        // assert!宏用于断言条件为真
        assert!(result.confidence >= 75);
    }

    /// 测试HTTP响应检测功能
    #[test]
    fn test_http_response_detection() {
        let detector = ProtocolDetector::new();

        // 模拟HTTP响应数据
        let http_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1024\r\n\r\n";

        let result = detector.detect(http_response).unwrap();

        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.direction, PacketDirection::ToClient); // 响应包
        assert_eq!(result.status_code, Some(200)); // 200状态码
        assert!(result.confidence >= 80);
    }

    /// 测试404响应检测
    #[test]
    fn test_http_404_detection() {
        let detector = ProtocolDetector::new();

        // 模拟404响应
        let not_found_response = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n";

        let result = detector.detect(not_found_response).unwrap();

        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.direction, PacketDirection::ToClient);
        assert_eq!(result.status_code, Some(404));
        assert!(result.confidence >= 80);
    }

    /// 测试HTTPS检测功能
    #[test]
    fn test_https_detection() {
        let detector = ProtocolDetector::new();

        // 模拟TLS 1.2握手开始的字节数据
        let tls_handshake = [
            0x16, 0x03, 0x03, 0x00, 0x40, // TLS记录头部
            0x01, 0x00, 0x00, 0x3c,       // 握手头部
        ];

        // &tls_handshake 创建数组的引用（切片）
        let result = detector.detect(&tls_handshake).unwrap();
        assert_eq!(result.protocol, Protocol::Https);
        assert_eq!(result.direction, PacketDirection::ToServer); // TLS握手是客户端发起的
        assert_eq!(result.status_code, None); // TLS握手没有HTTP状态码
    }

    /// 测试HTTP/2检测功能
    #[test]
    fn test_http2_detection() {
        let detector = ProtocolDetector::new();

        // HTTP/2连接前言（preface）
        let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let result = detector.detect(http2_preface).unwrap();

        assert_eq!(result.protocol, Protocol::Http2);
        assert_eq!(result.direction, PacketDirection::ToServer); // HTTP/2连接前言是请求包
        assert_eq!(result.confidence, 100);  // 应该是100%置信度
        assert_eq!(result.status_code, None);
    }

    /// 测试未知协议检测
    #[test]
    fn test_unknown_protocol() {
        let detector = ProtocolDetector::new();

        // 模拟未知协议的数据
        let unknown_data = b"UNKNOWN_PROTOCOL_DATA";
        let result = detector.detect(unknown_data).unwrap();

        // 应该检测为未知协议，置信度为0
        assert_eq!(result.protocol, Protocol::Unknown);
        assert_eq!(result.confidence, 0);
        assert_eq!(result.direction, PacketDirection::Unknown);
        assert_eq!(result.status_code, None);
    }
}