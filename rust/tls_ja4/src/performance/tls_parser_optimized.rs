//! 高性能TLS解析器
//! 
//! 使用内存池、缓存和SIMD优化来提升TLS解析性能

use tls_parser::{TlsVersion, TlsMessage, TlsMessageHandshake, TlsExtension};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

/// 高性能TLS解析器
pub struct OptimizedTlsParser {
    // 解析结果缓存
    cache: Arc<RwLock<HashMap<u64, ParsedTlsData>>>,
    // 内存池
    #[allow(dead_code)]
    buffer_pool: Arc<BufferPool>,
    // 预分配的解析缓冲区
    parse_buffer: Vec<u8>,
}

/// 解析后的TLS数据
#[derive(Debug, Clone)]
pub struct ParsedTlsData {
    pub version: TlsVersion,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub sni: Option<Vec<u8>>,
}

/// 内存池
pub struct BufferPool {
    cipher_buffers: Vec<Vec<u16>>,
    extension_buffers: Vec<Vec<u16>>,
    curve_buffers: Vec<Vec<u16>>,
    format_buffers: Vec<Vec<u8>>,
    string_buffers: Vec<String>,
}

impl BufferPool {
    pub fn new() -> Self {
        Self {
            cipher_buffers: Vec::new(),
            extension_buffers: Vec::new(),
            curve_buffers: Vec::new(),
            format_buffers: Vec::new(),
            string_buffers: Vec::new(),
        }
    }
    
    pub fn get_cipher_buffer(&mut self) -> Vec<u16> {
        self.cipher_buffers.pop().unwrap_or_else(|| Vec::with_capacity(64))
    }
    
    pub fn return_cipher_buffer(&mut self, mut buffer: Vec<u16>) {
        buffer.clear();
        if buffer.capacity() <= 128 {
            self.cipher_buffers.push(buffer);
        }
    }
    
    pub fn get_extension_buffer(&mut self) -> Vec<u16> {
        self.extension_buffers.pop().unwrap_or_else(|| Vec::with_capacity(32))
    }
    
    pub fn return_extension_buffer(&mut self, mut buffer: Vec<u16>) {
        buffer.clear();
        if buffer.capacity() <= 64 {
            self.extension_buffers.push(buffer);
        }
    }
    
    pub fn get_curve_buffer(&mut self) -> Vec<u16> {
        self.curve_buffers.pop().unwrap_or_else(|| Vec::with_capacity(16))
    }
    
    pub fn return_curve_buffer(&mut self, mut buffer: Vec<u16>) {
        buffer.clear();
        if buffer.capacity() <= 32 {
            self.curve_buffers.push(buffer);
        }
    }
    
    pub fn get_format_buffer(&mut self) -> Vec<u8> {
        self.format_buffers.pop().unwrap_or_else(|| Vec::with_capacity(8))
    }
    
    pub fn return_format_buffer(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();
        if buffer.capacity() <= 16 {
            self.format_buffers.push(buffer);
        }
    }
    
    pub fn get_string_buffer(&mut self) -> String {
        self.string_buffers.pop().unwrap_or_else(|| String::with_capacity(256))
    }
    
    pub fn return_string_buffer(&mut self, mut buffer: String) {
        buffer.clear();
        if buffer.capacity() <= 512 {
            self.string_buffers.push(buffer);
        }
    }
}

impl OptimizedTlsParser {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            buffer_pool: Arc::new(BufferPool::new()),
            parse_buffer: Vec::with_capacity(4096),
        }
    }
    
    /// 高性能TLS解析
    pub fn parse_tls_optimized(&mut self, payload: &[u8]) -> Option<ParsedTlsData> {
        // 快速失败检查
        if payload.len() < 5 {
            return None;
        }
        
        // 计算载荷哈希用于缓存
        let payload_hash = self.calculate_payload_hash(payload);
        
        // 检查缓存
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&payload_hash) {
                return Some(cached.clone());
            }
        }
        
        // 解析TLS
        let parsed = self.parse_tls_internal(payload)?;
        
        // 缓存结果
        {
            let mut cache = self.cache.write();
            if cache.len() < 1000 { // 限制缓存大小
                cache.insert(payload_hash, parsed.clone());
            }
        }
        
        Some(parsed)
    }
    
    /// 内部解析实现
    fn parse_tls_internal(&mut self, payload: &[u8]) -> Option<ParsedTlsData> {
        use tls_parser::parse_tls_plaintext;
        
        // 使用预分配缓冲区
        self.parse_buffer.clear();
        self.parse_buffer.extend_from_slice(payload);
        
        let (_, tls_plaintext) = parse_tls_plaintext(&self.parse_buffer).ok()?;
        let handshake = tls_plaintext.msg.first()?;
        
        if let TlsMessage::Handshake(handshake_msg) = handshake {
            if let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg {
                // 创建临时副本以避免借用冲突
                let mut temp_parser = OptimizedTlsParser::new();
                return temp_parser.parse_client_hello_optimized(client_hello);
            }
        }
        
        None
    }
    
    /// 优化的Client Hello解析
    fn parse_client_hello_optimized(&mut self, client_hello: &dyn tls_parser::ClientHello) -> Option<ParsedTlsData> {
        let mut ciphers = Vec::new();
        let mut extensions = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut signature_algorithms = Vec::new();
        let mut alpn_protocols = Vec::new();
        let mut sni = None;
        
        // 解析密码套件
        for cipher_suite in client_hello.cipher_suites() {
            if let Some(suite) = cipher_suite {
                ciphers.push(u16::from(suite.id));
            }
        }
        
        // 解析扩展
        if let Some(extensions_data) = client_hello.ext() {
            if let Ok((_, parsed_extensions)) = tls_parser::parse_tls_extensions(extensions_data) {
                for extension in parsed_extensions {
                    match extension {
                        TlsExtension::EllipticCurves(groups) => {
                            for group in groups {
                                elliptic_curves.push(group.0);
                            }
                        }
                        TlsExtension::EcPointFormats(formats) => {
                            ec_point_formats.extend_from_slice(formats);
                        }
                        TlsExtension::SignatureAlgorithms(algorithms) => {
                            signature_algorithms.extend_from_slice(&algorithms);
                        }
                        TlsExtension::ALPN(protocols) => {
                            for protocol in protocols {
                                alpn_protocols.push(protocol.to_vec());
                            }
                        }
                        TlsExtension::SNI(sni_data) => {
                            if let Some(server_name) = sni_data.first() {
                                sni = Some(server_name.1.to_vec());
                            }
                        }
                        _ => {
                            // 记录扩展类型
                            if let Some(ext_type) = self.get_extension_type(&extension) {
                                extensions.push(ext_type);
                            }
                        }
                    }
                }
            }
        }
        
        Some(ParsedTlsData {
            version: client_hello.version(),
            ciphers,
            extensions,
            elliptic_curves,
            ec_point_formats,
            signature_algorithms,
            alpn_protocols,
            sni,
        })
    }
    
    /// 获取扩展类型
    fn get_extension_type(&self, extension: &TlsExtension) -> Option<u16> {
        match extension {
            TlsExtension::SNI(_) => Some(0),
            TlsExtension::EllipticCurves(_) => Some(10),
            TlsExtension::EcPointFormats(_) => Some(11),
            TlsExtension::SignatureAlgorithms(_) => Some(13),
            TlsExtension::ALPN(_) => Some(16),
            TlsExtension::SupportedVersions(_) => Some(43),
            _ => None,
        }
    }
    
    /// 计算载荷哈希
    fn calculate_payload_hash(&self, payload: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        payload.hash(&mut hasher);
        hasher.finish()
    }
    
    /// 清理缓存
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write();
        cache.clear();
    }
    
    /// 获取缓存统计
    pub fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read();
        (cache.len(), cache.capacity())
    }
}

impl Default for OptimizedTlsParser {
    fn default() -> Self {
        Self::new()
    }
}

/// 批量TLS解析器
pub struct BatchTlsParser {
    parser: OptimizedTlsParser,
    #[allow(dead_code)]
    batch_size: usize,
}

impl BatchTlsParser {
    pub fn new(batch_size: usize) -> Self {
        Self {
            parser: OptimizedTlsParser::new(),
            batch_size,
        }
    }
    
    /// 批量解析TLS数据
    pub fn parse_batch(&mut self, payloads: &[&[u8]]) -> Vec<Option<ParsedTlsData>> {
        payloads.iter()
            .map(|payload| self.parser.parse_tls_optimized(payload))
            .collect()
    }
    
    /// 并行批量解析
    pub fn parse_batch_parallel(&mut self, payloads: &[&[u8]]) -> Vec<Option<ParsedTlsData>> {
        use rayon::prelude::*;
        
        payloads.par_iter()
            .map(|payload| {
                let mut temp_parser = OptimizedTlsParser::new();
                temp_parser.parse_tls_optimized(payload)
            })
            .collect()
    }
}

/// SIMD优化的字节操作
pub mod simd_utils {
    use std::arch::x86_64::*;
    
    /// SIMD优化的字节搜索
    pub unsafe fn find_byte_simd(haystack: &[u8], needle: u8) -> Option<usize> {
        if haystack.len() < 16 {
            return haystack.iter().position(|&b| b == needle);
        }
        
        let needle_vec = unsafe { _mm_set1_epi8(needle as i8) };
        let mut i = 0;
        
        while i + 16 <= haystack.len() {
            let chunk = unsafe { _mm_loadu_si128(haystack.as_ptr().add(i) as *const __m128i) };
            let cmp = unsafe { _mm_cmpeq_epi8(chunk, needle_vec) };
            let mask = unsafe { _mm_movemask_epi8(cmp) };
            
            if mask != 0 {
                return Some(i + mask.trailing_zeros() as usize);
            }
            
            i += 16;
        }
        
        // 处理剩余字节
        haystack[i..].iter().position(|&b| b == needle).map(|pos| i + pos)
    }
    
    /// SIMD优化的内存比较
    pub unsafe fn memcmp_simd(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        if a.len() < 16 {
            return a == b;
        }
        
        let mut i = 0;
        while i + 16 <= a.len() {
            let chunk_a = unsafe { _mm_loadu_si128(a.as_ptr().add(i) as *const __m128i) };
            let chunk_b = unsafe { _mm_loadu_si128(b.as_ptr().add(i) as *const __m128i) };
            let cmp = unsafe { _mm_cmpeq_epi8(chunk_a, chunk_b) };
            let mask = unsafe { _mm_movemask_epi8(cmp) };
            
            if mask != 0xFFFF {
                return false;
            }
            
            i += 16;
        }
        
        // 处理剩余字节
        a[i..] == b[i..]
    }
}
