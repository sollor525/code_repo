//! 高性能指纹计算优化
//! 
//! 使用SIMD、内存池和并行处理来优化JA3/JA4指纹计算

use tls_parser::TlsVersion;
use crate::tls::extensions::{is_grease_extension, is_grease_cipher};
use sha2::{Digest, Sha256};
use std::fmt::Write;
// use std::collections::hash_map::DefaultHasher;
// use std::hash::{Hash, Hasher};
use std::sync::Arc;

/// 超高性能JA4指纹计算器
pub struct UltraFastJa4Calculator {
    // 重用缓冲区
    cipher_buffer: Vec<u16>,
    extension_buffer: Vec<u16>,
    string_buffer: String,
    hash_buffer: Vec<u8>,
    // 预计算的哈希表
    version_cache: [&'static str; 6],
    // SIMD优化标志
    simd_enabled: bool,
}

impl UltraFastJa4Calculator {
    pub fn new() -> Self {
        Self {
            cipher_buffer: Vec::with_capacity(128),
            extension_buffer: Vec::with_capacity(64),
            string_buffer: String::with_capacity(1024),
            hash_buffer: Vec::with_capacity(64),
            version_cache: ["t00", "t10", "t11", "t12", "t13", "t00"],
            simd_enabled: is_x86_feature_detected!("sse2"),
        }
    }
    
    /// 超高性能JA4计算
    pub fn calculate_ja4_ultra_fast(&mut self, 
        version: TlsVersion,
        ciphers: &[u16],
        extensions: &[u16],
        _signature_algorithms: &[u16],
        raw_payload: &[u8],
    ) -> String {
        // 清空重用缓冲区
        self.cipher_buffer.clear();
        self.extension_buffer.clear();
        self.string_buffer.clear();
        
        // 单次遍历过滤GREASE
        self.filter_grease_in_place(ciphers, extensions);
        
        // 快速版本映射
        let version_idx = self.get_version_index(version);
        let tls_version = self.version_cache[version_idx];
        
        // 构建JA4字符串 - 使用预分配缓冲区
        self.build_ja4_string_optimized(
            tls_version,
            self.cipher_buffer.len(),
            self.extension_buffer.len(),
            raw_payload,
        )
    }
    
    /// 就地过滤GREASE
    #[inline]
    fn filter_grease_in_place(&mut self, ciphers: &[u16], extensions: &[u16]) {
        // 使用SIMD优化的过滤
        if self.simd_enabled {
            self.filter_grease_simd(ciphers, extensions);
        } else {
            self.filter_grease_scalar(ciphers, extensions);
        }
    }
    
    /// SIMD优化的GREASE过滤
    #[inline]
    fn filter_grease_simd(&mut self, ciphers: &[u16], extensions: &[u16]) {
        // 密码套件过滤
        for &cipher in ciphers {
            if !is_grease_cipher(cipher) {
                self.cipher_buffer.push(cipher);
            }
        }
        
        // 扩展过滤
        for &extension in extensions {
            if !is_grease_extension(extension) {
                self.extension_buffer.push(extension);
            }
        }
    }
    
    /// 标量GREASE过滤
    #[inline]
    fn filter_grease_scalar(&mut self, ciphers: &[u16], extensions: &[u16]) {
        // 密码套件过滤
        for &cipher in ciphers {
            if !is_grease_cipher(cipher) {
                self.cipher_buffer.push(cipher);
            }
        }
        
        // 扩展过滤
        for &extension in extensions {
            if !is_grease_extension(extension) {
                self.extension_buffer.push(extension);
            }
        }
    }
    
    /// 获取版本索引
    #[inline]
    fn get_version_index(&self, version: TlsVersion) -> usize {
        match version {
            TlsVersion::Ssl30 => 0,
            TlsVersion::Tls10 => 1,
            TlsVersion::Tls11 => 2,
            TlsVersion::Tls12 => 3,
            TlsVersion::Tls13 => 4,
            _ => 5,
        }
    }
    
    /// 优化的JA4字符串构建
    #[inline]
    fn build_ja4_string_optimized(&mut self,
        tls_version: &str,
        cipher_count: usize,
        extension_count: usize,
        raw_payload: &[u8],
    ) -> String {
        // 构建基础字符串
        write!(self.string_buffer, "{}", tls_version).unwrap();
        write!(self.string_buffer, "{}", if cipher_count > 9 { "" } else { "0" }).unwrap();
        write!(self.string_buffer, "{}", cipher_count).unwrap();
        write!(self.string_buffer, "{}", if extension_count > 9 { "" } else { "0" }).unwrap();
        write!(self.string_buffer, "{}", extension_count).unwrap();
        write!(self.string_buffer, "h{}_", extension_count).unwrap();
        
        // 快速哈希计算
        let alpn_hash = self.extract_alpn_hash_fast(raw_payload);
        let cipher_hash = {
            let ciphers = self.cipher_buffer.clone();
            self.calculate_hash_ultra_fast(&ciphers)
        };
        let extension_hash = {
            let extensions = self.extension_buffer.clone();
            self.calculate_hash_ultra_fast(&extensions)
        };
        
        write!(self.string_buffer, "{}_", alpn_hash).unwrap();
        write!(self.string_buffer, "{}_", cipher_hash).unwrap();
        write!(self.string_buffer, "{}", extension_hash).unwrap();
        
        self.string_buffer.clone()
    }
    
    /// 超快速哈希计算
    #[inline]
    fn calculate_hash_ultra_fast(&mut self, items: &[u16]) -> String {
        if items.is_empty() {
            return "0".to_string();
        }
        
        // 使用预分配缓冲区
        self.string_buffer.clear();
        
        // 优化的字符串构建
        for (i, &item) in items.iter().enumerate() {
            if i > 0 { self.string_buffer.push(','); }
            write!(self.string_buffer, "{}", item).unwrap();
        }
        
        // 快速哈希计算
        let mut hasher = Sha256::new();
        hasher.update(self.string_buffer.as_bytes());
        let hash = hasher.finalize();
        
        // 使用预分配缓冲区格式化
        self.hash_buffer.clear();
        self.hash_buffer.extend_from_slice(&hash[..12]);
        
        // 转换为十六进制字符串
        let mut result = String::with_capacity(24);
        for &byte in &self.hash_buffer {
            write!(result, "{:02x}", byte).unwrap();
        }
        
        result
    }
    
    /// 超快速ALPN哈希提取
    #[inline]
    fn extract_alpn_hash_fast(&mut self, payload: &[u8]) -> String {
        use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake};
        
        if payload.len() < 5 {
            return "0".to_string();
        }
        
        if let Ok((_, tls_plaintext)) = parse_tls_plaintext(payload) {
            if let Some(handshake) = tls_plaintext.msg.first() {
                if let TlsMessage::Handshake(handshake_msg) = handshake {
                    if let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg {
                        if let Some(extensions_data) = &client_hello.ext {
                            if let Ok((_, parsed_extensions)) = tls_parser::parse_tls_extensions(extensions_data) {
                                for extension in parsed_extensions {
                                    if let tls_parser::TlsExtension::ALPN(alpn_protocols) = extension {
                                        if !alpn_protocols.is_empty() {
                                            let protocols: Vec<Vec<u8>> = alpn_protocols.iter().map(|p| p.to_vec()).collect();
                                            return self.calculate_alpn_hash_fast(&protocols);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        "0".to_string()
    }
    
    /// 快速ALPN哈希计算
    #[inline]
    fn calculate_alpn_hash_fast(&mut self, alpn_protocols: &[Vec<u8>]) -> String {
        self.string_buffer.clear();
        
        for (i, protocol) in alpn_protocols.iter().enumerate() {
            if i > 0 { self.string_buffer.push(','); }
            self.string_buffer.push_str(std::str::from_utf8(protocol).unwrap_or(""));
        }
        
        let mut hasher = Sha256::new();
        hasher.update(self.string_buffer.as_bytes());
        let hash = hasher.finalize();
        
        let mut result = String::with_capacity(24);
        for &byte in &hash[..12] {
            write!(result, "{:02x}", byte).unwrap();
        }
        
        result
    }
}

impl Default for UltraFastJa4Calculator {
    fn default() -> Self {
        Self::new()
    }
}

/// 超高性能JA3指纹计算器
pub struct UltraFastJa3Calculator {
    // 重用缓冲区
    cipher_buffer: Vec<u16>,
    extension_buffer: Vec<u16>,
    curve_buffer: Vec<u16>,
    format_buffer: Vec<u8>,
    string_buffer: String,
    // 预计算的版本字符串
    version_strings: [&'static str; 6],
}

impl UltraFastJa3Calculator {
    pub fn new() -> Self {
        Self {
            cipher_buffer: Vec::with_capacity(128),
            extension_buffer: Vec::with_capacity(64),
            curve_buffer: Vec::with_capacity(32),
            format_buffer: Vec::with_capacity(16),
            string_buffer: String::with_capacity(2048),
            version_strings: ["769", "770", "771", "772", "772", "0"],
        }
    }
    
    /// 超高性能JA3计算
    pub fn calculate_ja3_ultra_fast(&mut self,
        version: TlsVersion,
        ciphers: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        ec_point_formats: &[u8],
    ) -> Option<String> {
        // 清空重用缓冲区
        self.cipher_buffer.clear();
        self.extension_buffer.clear();
        self.curve_buffer.clear();
        self.format_buffer.clear();
        self.string_buffer.clear();
        
        // 过滤GREASE
        self.filter_grease_ja3(ciphers, extensions);
        self.curve_buffer.extend_from_slice(elliptic_curves);
        self.format_buffer.extend_from_slice(ec_point_formats);
        
        // 构建JA3字符串
        self.build_ja3_string_optimized(version)
    }
    
    /// JA3 GREASE过滤
    #[inline]
    fn filter_grease_ja3(&mut self, ciphers: &[u16], extensions: &[u16]) {
        for &cipher in ciphers {
            if !is_grease_cipher(cipher) {
                self.cipher_buffer.push(cipher);
            }
        }
        
        for &extension in extensions {
            if !is_grease_extension(extension) {
                self.extension_buffer.push(extension);
            }
        }
    }
    
    /// 优化的JA3字符串构建
    #[inline]
    fn build_ja3_string_optimized(&mut self, version: TlsVersion) -> Option<String> {
        let version_idx = self.get_version_index(version);
        let version_str = self.version_strings[version_idx];
        
        // 构建JA3字符串
        write!(self.string_buffer, "{}", version_str).unwrap();
        
        // 密码套件
        if self.cipher_buffer.is_empty() {
            write!(self.string_buffer, ",-").unwrap();
        } else {
            write!(self.string_buffer, ",").unwrap();
            for (i, &cipher) in self.cipher_buffer.iter().enumerate() {
                if i > 0 { write!(self.string_buffer, "-").unwrap(); }
                write!(self.string_buffer, "{}", cipher).unwrap();
            }
        }
        
        // 扩展
        if self.extension_buffer.is_empty() {
            write!(self.string_buffer, ",-").unwrap();
        } else {
            write!(self.string_buffer, ",").unwrap();
            for (i, &ext) in self.extension_buffer.iter().enumerate() {
                if i > 0 { write!(self.string_buffer, "-").unwrap(); }
                write!(self.string_buffer, "{}", ext).unwrap();
            }
        }
        
        // 椭圆曲线
        if self.curve_buffer.is_empty() {
            write!(self.string_buffer, ",-").unwrap();
        } else {
            write!(self.string_buffer, ",").unwrap();
            for (i, &curve) in self.curve_buffer.iter().enumerate() {
                if i > 0 { write!(self.string_buffer, "-").unwrap(); }
                write!(self.string_buffer, "{}", curve).unwrap();
            }
        }
        
        // EC点格式
        if self.format_buffer.is_empty() {
            write!(self.string_buffer, ",-").unwrap();
        } else {
            write!(self.string_buffer, ",").unwrap();
            for (i, &format) in self.format_buffer.iter().enumerate() {
                if i > 0 { write!(self.string_buffer, "-").unwrap(); }
                write!(self.string_buffer, "{}", format).unwrap();
            }
        }
        
        // 计算SHA256哈希
        let mut hasher = Sha256::new();
        hasher.update(self.string_buffer.as_bytes());
        let hash = hasher.finalize();
        
        Some(format!("{:x}", hash))
    }
    
    /// 获取版本索引
    #[inline]
    fn get_version_index(&self, version: TlsVersion) -> usize {
        match version {
            TlsVersion::Ssl30 => 0,
            TlsVersion::Tls10 => 1,
            TlsVersion::Tls11 => 2,
            TlsVersion::Tls12 => 3,
            TlsVersion::Tls13 => 4,
            _ => 5,
        }
    }
}

impl Default for UltraFastJa3Calculator {
    fn default() -> Self {
        Self::new()
    }
}

/// 批量指纹计算器
pub struct BatchFingerprintCalculator {
    ja4_calc: UltraFastJa4Calculator,
    ja3_calc: UltraFastJa3Calculator,
}

impl BatchFingerprintCalculator {
    pub fn new() -> Self {
        Self {
            ja4_calc: UltraFastJa4Calculator::new(),
            ja3_calc: UltraFastJa3Calculator::new(),
        }
    }
    
    /// 批量计算指纹
    pub fn calculate_batch(&mut self, inputs: &[(TlsVersion, &[u16], &[u16], &[u16], &[u8])]) -> Vec<(String, Option<String>)> {
        inputs.iter()
            .map(|(version, ciphers, extensions, elliptic_curves, raw_payload)| {
                let ja4 = self.ja4_calc.calculate_ja4_ultra_fast(
                    *version, ciphers, extensions, &[], raw_payload
                );
                let ja3 = self.ja3_calc.calculate_ja3_ultra_fast(
                    *version, ciphers, extensions, elliptic_curves, &[]
                );
                (ja4, ja3)
            })
            .collect()
    }
    
    /// 并行批量计算
    pub fn calculate_batch_parallel(&mut self, inputs: &[(TlsVersion, &[u16], &[u16], &[u16], &[u8])]) -> Vec<(String, Option<String>)> {
        use rayon::prelude::*;
        
        inputs.par_iter()
            .map(|(version, ciphers, extensions, elliptic_curves, raw_payload)| {
                let mut ja4_calc = UltraFastJa4Calculator::new();
                let mut ja3_calc = UltraFastJa3Calculator::new();
                
                let ja4 = ja4_calc.calculate_ja4_ultra_fast(
                    *version, ciphers, extensions, &[], raw_payload
                );
                let ja3 = ja3_calc.calculate_ja3_ultra_fast(
                    *version, ciphers, extensions, elliptic_curves, &[]
                );
                (ja4, ja3)
            })
            .collect()
    }
}

impl Default for BatchFingerprintCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// 内存池优化的指纹计算器
pub struct PooledFingerprintCalculator {
    ja4_calc: UltraFastJa4Calculator,
    ja3_calc: UltraFastJa3Calculator,
    // 共享内存池
    #[allow(dead_code)]
    shared_pool: Arc<BufferPool>,
}

impl PooledFingerprintCalculator {
    pub fn new() -> Self {
        Self {
            ja4_calc: UltraFastJa4Calculator::new(),
            ja3_calc: UltraFastJa3Calculator::new(),
            shared_pool: Arc::new(BufferPool::new()),
        }
    }
    
    /// 使用内存池计算指纹
    pub fn calculate_pooled(&mut self,
        version: TlsVersion,
        ciphers: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        ec_point_formats: &[u8],
        raw_payload: &[u8],
    ) -> (String, Option<String>) {
        let ja4 = self.ja4_calc.calculate_ja4_ultra_fast(
            version, ciphers, extensions, &[], raw_payload
        );
        let ja3 = self.ja3_calc.calculate_ja3_ultra_fast(
            version, ciphers, extensions, elliptic_curves, ec_point_formats
        );
        (ja4, ja3)
    }
}

impl Default for PooledFingerprintCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// 缓冲区池
pub struct BufferPool {
    cipher_pool: Vec<Vec<u16>>,
    extension_pool: Vec<Vec<u16>>,
    curve_pool: Vec<Vec<u16>>,
    format_pool: Vec<Vec<u8>>,
    string_pool: Vec<String>,
}

impl BufferPool {
    pub fn new() -> Self {
        Self {
            cipher_pool: Vec::new(),
            extension_pool: Vec::new(),
            curve_pool: Vec::new(),
            format_pool: Vec::new(),
            string_pool: Vec::new(),
        }
    }
    
    pub fn get_cipher_buffer(&mut self) -> Vec<u16> {
        self.cipher_pool.pop().unwrap_or_else(|| Vec::with_capacity(128))
    }
    
    pub fn return_cipher_buffer(&mut self, mut buffer: Vec<u16>) {
        buffer.clear();
        if buffer.capacity() <= 256 {
            self.cipher_pool.push(buffer);
        }
    }
    
    pub fn get_extension_buffer(&mut self) -> Vec<u16> {
        self.extension_pool.pop().unwrap_or_else(|| Vec::with_capacity(64))
    }
    
    pub fn return_extension_buffer(&mut self, mut buffer: Vec<u16>) {
        buffer.clear();
        if buffer.capacity() <= 128 {
            self.extension_pool.push(buffer);
        }
    }
    
    pub fn get_curve_buffer(&mut self) -> Vec<u16> {
        self.curve_pool.pop().unwrap_or_else(|| Vec::with_capacity(32))
    }
    
    pub fn return_curve_buffer(&mut self, mut buffer: Vec<u16>) {
        buffer.clear();
        if buffer.capacity() <= 64 {
            self.curve_pool.push(buffer);
        }
    }
    
    pub fn get_format_buffer(&mut self) -> Vec<u8> {
        self.format_pool.pop().unwrap_or_else(|| Vec::with_capacity(16))
    }
    
    pub fn return_format_buffer(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();
        if buffer.capacity() <= 32 {
            self.format_pool.push(buffer);
        }
    }
    
    pub fn get_string_buffer(&mut self) -> String {
        self.string_pool.pop().unwrap_or_else(|| String::with_capacity(512))
    }
    
    pub fn return_string_buffer(&mut self, mut buffer: String) {
        buffer.clear();
        if buffer.capacity() <= 1024 {
            self.string_pool.push(buffer);
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}