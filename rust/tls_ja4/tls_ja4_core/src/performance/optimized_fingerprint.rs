//! 优化的指纹计算模块
//!
//! 提供高性能的JA4/JA3指纹计算功能

use crate::performance::optimized_strings::*;
use crate::utils::is_grease_value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

/// 优化的指纹计算器
pub struct OptimizedFingerprintCalculator {
    hex_encoder: HexEncoder,
    string_pool: StringPool,
    buffer: Vec<u8>,
}

impl OptimizedFingerprintCalculator {
    /// 创建新的指纹计算器
    pub fn new() -> Self {
        Self {
            hex_encoder: HexEncoder::new(),
            string_pool: StringPool::new(),
            buffer: Vec::with_capacity(1024),
        }
    }

    /// 计算优化的JA4指纹
    pub fn calculate_ja4(
        &mut self,
        version: tls_parser::TlsVersion,
        cipher_suites: &[u16],
        extensions: &[u16],
        signature_algorithms: &[u16],
        client_hello_data: &[u8],
    ) -> String {
        // 1. 计算JA4_a部分
        let ja4_a = self.calculate_ja4_a(version, extensions, cipher_suites, client_hello_data);

        // 2. 计算JA4_b部分（密码套件哈希）
        let ja4_b = self.calculate_ja4_b(cipher_suites);

        // 3. 计算JA4_c部分（扩展哈希）
        let ja4_c = self.calculate_ja4_c(extensions, signature_algorithms);

        // 4. 组合最终结果
        let mut result = StringBuilder::with_capacity(ja4_a.len() + ja4_b.len() + ja4_c.len() + 2);
        result.push_str(&ja4_a).push_char('_').push_str(&ja4_b).push_char('_').push_str(&ja4_c);
        result.finish()
    }

    /// 计算JA4_a部分
    fn calculate_ja4_a(&mut self, version: tls_parser::TlsVersion, extensions: &[u16], cipher_suites: &[u16], client_hello_data: &[u8]) -> String {
        // 协议标识
        let protocol = "t";

        // TLS版本
        let version_str = self.get_tls_version_string(version, protocol, extensions);

        // SNI标志
        let sni_flag = if extensions.contains(&0) { "d" } else { "i" };

        // 密码套件计数
        let cipher_count = self.count_non_grease_values(cipher_suites);

        // 扩展计数
        let extension_count = self.count_non_grease_values(extensions);

        // ALPN
        let alpn_flag = self.extract_alpn_optimized(client_hello_data);

        // 构建JA4_a
        let mut result = StringBuilder::with_capacity(16);
        result.push_str(&version_str)
            .push_str(sni_flag)
            .push_str(&format_u8_with_zero(cipher_count))
            .push_str(&format_u8_with_zero(extension_count))
            .push_str(&alpn_flag);

        result.finish()
    }

    /// 获取TLS版本字符串
    fn get_tls_version_string(&mut self, version: tls_parser::TlsVersion, protocol: &str, extensions: &[u16]) -> Cow<'static, str> {
        use tls_parser::TlsVersion;

        // 检查是否有supported_versions扩展
        let highest_version = if extensions.contains(&43) {
            TlsVersion::Tls13
        } else {
            version
        };

        match highest_version {
            TlsVersion::Ssl30 => Cow::Owned(format!("{}s3", protocol)),
            TlsVersion::Tls10 => Cow::Owned(format!("{}10", protocol)),
            TlsVersion::Tls11 => Cow::Owned(format!("{}11", protocol)),
            TlsVersion::Tls12 => Cow::Owned(format!("{}12", protocol)),
            TlsVersion::Tls13 => Cow::Owned(format!("{}13", protocol)),
            _ => Cow::Owned(format!("{}00", protocol)),
        }
    }

    /// 计算非GREASE值的数量
    fn count_non_grease_values(&self, values: &[u16]) -> u8 {
        values.iter()
            .filter(|&&v| !is_grease_value(v))
            .count() as u8
    }

    /// 优化的ALPN提取
    fn extract_alpn_optimized(&mut self, client_hello_data: &[u8]) -> String {
        // 使用缓存的解析结果
        if let Some(alpn) = self.extract_alpn_fast(client_hello_data) {
            return alpn;
        }

        constants::UNKNOWN_ALPN.to_string()
    }

    /// 快速ALPN提取
    fn extract_alpn_fast(&mut self, client_hello_data: &[u8]) -> Option<String> {
        use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};

        // 解析TLS包
        if let Ok((_, tls_plaintext)) = parse_tls_plaintext(client_hello_data) {
            if let Some(handshake) = tls_plaintext.msg.first() {
                if let TlsMessage::Handshake(handshake_msg) = handshake {
                    if let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg {
                        // 查找ALPN扩展
                        if let Some(extensions_data) = &client_hello.ext {
                            if let Ok((_, parsed_extensions)) = tls_parser::parse_tls_extensions(extensions_data) {
                                for extension in parsed_extensions {
                                    if let tls_parser::TlsExtension::ALPN(alpn_protocols) = extension {
                                        if !alpn_protocols.is_empty() {
                                            let first_protocol = &alpn_protocols[0];
                                            let protocol_str = std::str::from_utf8(first_protocol).unwrap_or("");
                                            return Some(map_alpn_protocol(protocol_str).into_owned());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// 计算JA4_b（密码套件哈希）
    fn calculate_ja4_b(&mut self, cipher_suites: &[u16]) -> String {
        // 过滤并排序密码套件
        self.buffer.clear();
        let mut sorted_ciphers: Vec<u16> = cipher_suites.iter()
            .filter(|&&c| !is_grease_value(c))
            .copied()
            .collect();
        sorted_ciphers.sort();

        // 构建密码套件字符串
        let mut need_comma = false;
        for &cipher in &sorted_ciphers {
            if need_comma {
                self.buffer.push(b',');
            }
            let hex_str = u16_to_hex_string(cipher);
            self.buffer.extend_from_slice(hex_str.as_bytes());
            need_comma = true;
        }

        // 计算SHA256哈希
        let mut hasher = Sha256::new();
        hasher.update(&self.buffer);
        let hash = hasher.finalize();

        // 返回前12位
        self.hex_encoder.encode(&hash[..6])
    }

    /// 计算JA4_c（扩展哈希）
    fn calculate_ja4_c(&mut self, extensions: &[u16], signature_algorithms: &[u16]) -> String {
        self.buffer.clear();

        // 处理扩展（过滤SNI和ALPN）
        let mut filtered_extensions: Vec<u16> = extensions.iter()
            .filter(|&&ext| {
                !is_grease_value(ext) && ext != 0x0000 && ext != 0x0010
            })
            .copied()
            .collect();
        filtered_extensions.sort();

        // 构建扩展字符串
        let mut need_comma = false;
        for &ext in &filtered_extensions {
            if need_comma {
                self.buffer.push(b',');
            }
            let hex_str = u16_to_hex_string(ext);
            self.buffer.extend_from_slice(hex_str.as_bytes());
            need_comma = true;
        }

        // 处理签名算法
        let filtered_sig_algs: Vec<u16> = signature_algorithms.iter()
            .filter(|&&s| !is_grease_value(s))
            .copied()
            .collect();

        if !filtered_sig_algs.is_empty() {
            self.buffer.push(b'_');
            let mut need_comma = false;
            for &sig in &filtered_sig_algs {
                if need_comma {
                    self.buffer.push(b',');
                }
                let hex_str = u16_to_hex_string(sig);
                self.buffer.extend_from_slice(hex_str.as_bytes());
                need_comma = true;
            }
        }

        // 计算SHA256哈希
        let mut hasher = Sha256::new();
        hasher.update(&self.buffer);
        let hash = hasher.finalize();

        // 返回前12位
        self.hex_encoder.encode(&hash[..6])
    }

    /// 计算优化的JA3指纹
    pub fn calculate_ja3(
        &mut self,
        version: tls_parser::TlsVersion,
        cipher_suites: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        ec_point_formats: &[u8],
    ) -> Option<String> {
        // 构建JA3字符串
        let mut builder = StringBuilder::with_capacity(256);

        // TLS版本
        builder.push_str(&self.get_ja3_version_string(version));

        // 密码套件（保持原始顺序）
        builder.push_char(',');
        self.append_non_grease_values_u16(&mut builder, cipher_suites, constants::DASH);

        // 扩展（保持原始顺序）
        builder.push_char(',');
        self.append_non_grease_values_u16(&mut builder, extensions, constants::DASH);

        // 椭圆曲线
        builder.push_char(',');
        if elliptic_curves.is_empty() {
            builder.push_str("29-23-30-25-24");
        } else {
            self.append_non_grease_values_u16(&mut builder, elliptic_curves, constants::DASH);
        }

        // 点格式
        builder.push_char(',');
        if ec_point_formats.is_empty() {
            builder.push_str("0-1-2");
        } else {
            self.append_non_grease_values_u8(&mut builder, ec_point_formats, constants::DASH);
        }

        let ja3_string = builder.finish();

        // 计算MD5哈希
        let hash = md5::compute(ja3_string.as_bytes());
        Some(format!("{:x}", hash))
    }

    /// 获取JA3版本字符串
    fn get_ja3_version_string(&self, version: tls_parser::TlsVersion) -> &'static str {
        use tls_parser::TlsVersion;
        match version {
            TlsVersion::Ssl30 => "768",
            TlsVersion::Tls10 => "769",
            TlsVersion::Tls11 => "770",
            TlsVersion::Tls12 => "771",
            TlsVersion::Tls13 => "772",
            _ => "0",
        }
    }

    /// 追加非GREASE的u16值
    fn append_non_grease_values_u16(&self, builder: &mut StringBuilder, values: &[u16], separator: &str) {
        let mut first = true;
        for &value in values {
            if !is_grease_value(value) {
                if !first {
                    builder.push_str(separator);
                }
                builder.push_str(&value.to_string());
                first = false;
            }
        }
    }

    /// 追加非GREASE的u8值
    fn append_non_grease_values_u8(&self, builder: &mut StringBuilder, values: &[u8], separator: &str) {
        let mut first = true;
        for &value in values {
            if !is_grease_value(value as u16) {
                if !first {
                    builder.push_str(separator);
                }
                builder.push_str(&value.to_string());
                first = false;
            }
        }
    }

    /// 清理缓存
    pub fn clear_cache(&mut self) {
        self.string_pool.clear();
        self.buffer.clear();
        self.buffer.shrink_to_fit();
    }

    /// 获取缓存大小
    pub fn len(&self) -> usize {
        self.string_pool.len()
    }

    /// 检查缓存是否为空
    pub fn is_empty(&self) -> bool {
        self.string_pool.is_empty()
    }
}

impl Default for OptimizedFingerprintCalculator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimized_ja4_calculation() {
        let mut calculator = OptimizedFingerprintCalculator::new();

        let cipher_suites = vec![0x1301, 0x1302, 0x1303];
        let extensions = vec![0x0000, 0x0005, 0x000a, 0x000b, 0x0023];
        let signature_algs = vec![0x0403, 0x0804, 0x0401, 0x0805, 0x0806, 0x0401, 0x0501, 0x0503, 0x0502, 0x0403, 0x0804, 0x0501, 0x0503, 0x0502];

        let result = calculator.calculate_ja4(
            tls_parser::TlsVersion::Tls13,
            &cipher_suites,
            &extensions,
            &signature_algs,
            &[], // 简化测试，不提供完整client hello数据
        );

        assert!(!result.is_empty());
        assert!(result.contains('_'));
    }

    #[test]
    fn test_alpn_mapping() {
        // 测试不同的ALPN协议
        let test_protocols = vec![
            ("h2", "http/2"),
            ("h1", "http/1.1"),
            ("gr", "grpc"),
            ("h3", "http/3"),
        ];

        for (expected, input) in test_protocols {
            assert_eq!(map_alpn_protocol(input), expected);
        }
    }
}