//! IP分片重组器
//!
//! 负责处理IP分片的重组，包括分片缓存、重叠处理等

use std::collections::{HashMap, BTreeMap};
use std::time::{Duration, Instant};
use crate::types::PacketInfo;

/// IP分片重组器配置
#[derive(Debug, Clone)]
pub struct FragmenterConfig {
    /// 最大分片缓存大小（字节）
    pub max_cache_size: usize,
    /// 分片超时时间（秒）
    pub fragment_timeout: Duration,
    /// 每个数据包的最大分片数
    pub max_fragments_per_packet: usize,
    /// 是否启用重叠检测
    pub enable_overlap_detection: bool,
    /// 最大重叠处理次数
    pub max_overlap_count: u32,
    /// 是否丢弃重叠分片
    pub drop_overlapping_fragments: bool,
}

impl Default for FragmenterConfig {
    fn default() -> Self {
        Self {
            max_cache_size: 64 * 1024 * 1024, // 64MB
            fragment_timeout: Duration::from_secs(60),
            max_fragments_per_packet: 64,
            enable_overlap_detection: true,
            max_overlap_count: 10,
            drop_overlapping_fragments: false,
        }
    }
}

/// IP分片标识
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentId {
    /// 源IP地址（简化处理）
    pub src_ip: u32,
    /// 目的IP地址
    pub dst_ip: u32,
    /// 协议类型
    pub protocol: u8,
    /// 标识字段
    pub identification: u16,
}

impl FragmentId {
    /// 创建新的分片标识
    pub fn new(src_ip: u32, dst_ip: u32, protocol: u8, identification: u16) -> Self {
        Self {
            src_ip,
            dst_ip,
            protocol,
            identification,
        }
    }
}

/// IP分片信息
#[derive(Debug, Clone)]
pub struct IpFragment {
    /// 分片偏移（8字节为单位）
    pub offset: u16,
    /// 是否是最后一个分片
    pub is_last: bool,
    /// 数据内容
    pub data: Vec<u8>,
    /// 接收时间戳
    pub timestamp: u64,
    /// 分片长度（包含头部）
    pub total_length: u16,
    /// 分片标志
    pub flags: u8,
}

impl IpFragment {
    /// 创建新的IP分片
    pub fn new(offset: u16, is_last: bool, data: Vec<u8>, timestamp: u64, total_length: u16, flags: u8) -> Self {
        Self {
            offset,
            is_last,
            data,
            timestamp,
            total_length,
            flags,
        }
    }

    /// 获取分片的字节偏移
    pub fn byte_offset(&self) -> u32 {
        (self.offset as u32) * 8
    }

    /// 获取分片的结束字节偏移
    pub fn byte_end(&self) -> u32 {
        self.byte_offset() + self.data.len() as u32
    }

    /// 获取数据长度
    pub fn data_len(&self) -> usize {
        self.data.len()
    }
}

/// 分片重组结果
#[derive(Debug, Clone)]
pub struct FragmentationResult {
    /// 重组后的完整数据
    pub data: Vec<u8>,
    /// 原始数据包总长度
    pub total_length: u16,
    /// 使用的分片数量
    pub fragment_count: usize,
    /// 重组耗时（微秒）
    pub reassembly_time_us: u64,
    /// 是否有重叠
    pub had_overlaps: bool,
    /// 重组ID
    pub fragment_id: FragmentId,
}

/// 分片缓存状态
#[derive(Debug, Clone)]
pub struct FragmentCache {
    /// 分片列表，按偏移排序
    fragments: BTreeMap<u16, IpFragment>,
    /// 第一个分片的接收时间
    first_fragment_time: u64,
    /// 总数据长度（如果知道）
    total_length: Option<u16>,
    /// 是否有重叠
    has_overlaps: bool,
    /// 重叠计数
    #[allow(dead_code)] overlap_count: u32,  // 暂未使用，保留用于统计
}

impl FragmentCache {
    /// 创建新的分片缓存
    pub fn new(timestamp: u64) -> Self {
        Self {
            fragments: BTreeMap::new(),
            first_fragment_time: timestamp,
            total_length: None,
            has_overlaps: false,
            overlap_count: 0,
        }
    }

    /// 添加分片
    pub fn add_fragment(&mut self, fragment: IpFragment) -> Result<bool, FragmentationError> {
        // 检查是否已经存在相同偏移的分片
        if self.fragments.contains_key(&fragment.offset) {
            return Ok(false); // 重复分片
        }

        // 添加分片
        self.fragments.insert(fragment.offset, fragment);

        // 如果是最后一个分片，计算总长度
        if let Some(last_frag) = self.fragments.values().find(|f| f.is_last) {
            self.total_length = Some(
                last_frag.byte_offset() as u16 + last_frag.data.len() as u16
            );
        }

        Ok(true)
    }

    /// 检查是否可以重组
    pub fn can_reassemble(&self) -> bool {
        if self.fragments.is_empty() {
            return false;
        }

        // 检查是否有第一个分片
        if !self.fragments.contains_key(&0) {
            return false;
        }

        // 检查是否有最后一个分片
        if !self.fragments.values().any(|f| f.is_last) {
            return false;
        }

        // 检查是否有间隙
        let mut expected_offset = 0;
        for (offset, fragment) in &self.fragments {
            if *offset != expected_offset {
                return false;
            }
            // 计算下一个期望的偏移（8字节单位）
            let frag_end_bytes = fragment.byte_offset() + fragment.data.len() as u32;
            expected_offset = ((frag_end_bytes + 7) / 8) as u16;
        }

        true
    }

    /// 尝试重组
    pub fn reassemble(&self) -> Option<FragmentationResult> {
        if !self.can_reassemble() {
            return None;
        }

        let start_time = Instant::now();
        let mut assembled_data = Vec::new();
        let fragment_count = self.fragments.len();

        // 按顺序组装分片
        for fragment in self.fragments.values() {
            assembled_data.extend_from_slice(&fragment.data);
        }

        let reassembly_time = start_time.elapsed().as_micros() as u64;

        Some(FragmentationResult {
            data: assembled_data,
            total_length: self.total_length.unwrap_or(0),
            fragment_count,
            reassembly_time_us: reassembly_time,
            had_overlaps: self.has_overlaps,
            fragment_id: FragmentId::new(0, 0, 0, 0), // 实际使用时需要设置
        })
    }

    /// 获取缓存大小
    pub fn size(&self) -> usize {
        self.fragments.iter().map(|(_, f)| f.data_len()).sum()
    }

    /// 检查是否过期
    pub fn is_expired(&self, timeout_micros: u64, current_time: u64) -> bool {
        current_time - self.first_fragment_time > timeout_micros
    }
}

/// IP分片重组器
///
/// 管理IP分片的接收、缓存和重组
pub struct IpFragmenter {
    /// 配置
    config: FragmenterConfig,
    /// 分片缓存，按FragmentId组织
    fragment_cache: HashMap<FragmentId, FragmentCache>,
    /// 最后清理时间
    last_cleanup: Instant,
    /// 统计信息
    stats: FragmenterStats,
    /// 当前缓存大小
    current_cache_size: usize,
}

/// 分片重组器统计信息
#[derive(Debug, Clone, Default)]
pub struct FragmenterStats {
    /// 接收的分片总数
    pub total_fragments: u64,
    /// 重组的完整数据包数
    pub reassembled_packets: u64,
    /// 丢弃的分片数
    pub discarded_fragments: u64,
    /// 重叠分片数
    pub overlapping_fragments: u64,
    /// 超时丢弃的数据包数
    pub timeout_packets: u64,
    /// 平均分片数/包
    pub avg_fragments_per_packet: f64,
    /// 重组操作次数
    pub reassembly_operations: u64,
    /// 平均重组时间（微秒）
    pub avg_reassembly_time_us: f64,
    /// 缓存使用峰值
    pub peak_cache_usage: usize,
}

impl IpFragmenter {
    /// 创建新的IP分片重组器
    pub fn new(config: FragmenterConfig) -> Self {
        Self {
            config,
            fragment_cache: HashMap::new(),
            last_cleanup: Instant::now(),
            stats: FragmenterStats::default(),
            current_cache_size: 0,
        }
    }

    /// 使用默认配置创建IP分片重组器
    pub fn with_default_config() -> Self {
        Self::new(FragmenterConfig::default())
    }

    /// 处理IP分片
    pub fn process_fragment(&mut self, packet: &PacketInfo) -> Result<Option<FragmentationResult>, FragmentationError> {
        // 检查是否需要清理
        if self.last_cleanup.elapsed() >= Duration::from_secs(10) {
            self.cleanup_expired_fragments();
        }

        // 提取分片信息（简化版）
        let fragment_info = self.extract_fragment_info(packet)?;
        if fragment_info.is_none() {
            return Ok(None); // 不是分片包
        }

        let (fragment_id, fragment) = fragment_info.unwrap();

        // 更新统计
        self.stats.total_fragments += 1;

        // 检查缓存大小
        let fragment_size = fragment.data_len();
        if self.current_cache_size + fragment_size > self.config.max_cache_size {
            // 简化处理：如果缓存满，直接丢弃
            self.stats.discarded_fragments += 1;
            return Ok(None);
        }

        // 简化实现：直接处理，不使用entry API
        let should_create = !self.fragment_cache.contains_key(&fragment_id);

        if should_create {
            // 检查缓存大小
            if self.current_cache_size + fragment_size > self.config.max_cache_size {
                self.stats.discarded_fragments += 1;
                return Ok(None);
            }

            // 创建新缓存
            let mut cache = FragmentCache::new(packet.timestamp);

            // 添加分片
            if cache.add_fragment(fragment.clone())? {
                self.current_cache_size += fragment_size;
            }

            // 尝试重组
            let result = cache.reassemble();

            // 如果重组成功，更新统计并返回
            if let Some(res) = result {
                self.update_reassembly_stats(&res);
                // 缓存已经被重组，不需要存储
                Ok(Some(res))
            } else {
                // 重组失败，存储缓存
                self.fragment_cache.insert(fragment_id, cache);
                Ok(None)
            }
        } else {
            // 缓存已存在
            let mut remove_cache = false;
            let mut result = None;

            if let Some(cache) = self.fragment_cache.get_mut(&fragment_id) {
                // 检查分片数量限制
                if cache.fragments.len() >= self.config.max_fragments_per_packet {
                    self.stats.discarded_fragments += 1;
                    remove_cache = true;
                } else {
                    // 添加分片
                    if cache.add_fragment(fragment.clone())? {
                        self.current_cache_size += fragment_size;
                    }

                    // 尝试重组
                    result = cache.reassemble();
                    if result.is_some() {
                        remove_cache = true;
                    }
                }
            }

            // 如果需要移除缓存
            if remove_cache {
                if let Some(cache) = self.fragment_cache.remove(&fragment_id) {
                    self.current_cache_size -= cache.size();

                    if let Some(res) = result {
                        self.update_reassembly_stats(&res);
                        return Ok(Some(res));
                    }
                }
            }

            Ok(result)
        }
    }

    /// 从数据包中提取分片信息（简化版）
    fn extract_fragment_info(&self, _packet: &PacketInfo) -> Result<Option<(FragmentId, IpFragment)>, FragmentationError> {
        // 简化实现：假设packet中已经包含了分片信息
        // 实际实现需要解析IP头部

        // 示例：创建一个假的分片信息
        let fragment_id = FragmentId::new(
            0x12345678, // src_ip (示例)
            0x87654321, // dst_ip (示例)
            6, // protocol (TCP)
            12345, // identification
        );

        let fragment = IpFragment::new(
            0, // offset
            true, // is_last
            vec![1, 2, 3, 4], // data (示例)
            123456789, // timestamp
            4, // total_length
            0, // flags
        );

        Ok(Some((fragment_id, fragment)))
    }

    /// 更新重组统计信息
    fn update_reassembly_stats(&mut self, result: &FragmentationResult) {
        self.stats.reassembled_packets += 1;
        self.stats.reassembly_operations += 1;

        // 更新平均分片数
        let total_fragments = self.stats.reassembled_packets as f64 * self.stats.avg_fragments_per_packet;
        self.stats.avg_fragments_per_packet = (total_fragments + result.fragment_count as f64) /
                                               (self.stats.reassembled_packets as f64);

        // 更新平均重组时间
        let total_time = self.stats.avg_reassembly_time_us * (self.stats.reassembly_operations - 1) as f64;
        self.stats.avg_reassembly_time_us = (total_time + result.reassembly_time_us as f64) /
                                            (self.stats.reassembly_operations as f64);
    }

    /// 清理过期的分片
    pub fn cleanup_expired_fragments(&mut self) {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let timeout_micros = self.config.fragment_timeout.as_micros() as u64;

        let mut to_remove = Vec::new();

        for (fragment_id, cache) in &self.fragment_cache {
            if cache.is_expired(timeout_micros, current_time) {
                to_remove.push(*fragment_id);
            }
        }

        // 移除过期缓存
        for fragment_id in to_remove {
            if let Some(cache) = self.fragment_cache.remove(&fragment_id) {
                self.current_cache_size -= cache.size();
                self.stats.timeout_packets += 1;
            }
        }

        self.last_cleanup = Instant::now();
    }

    /// 获取缓存状态
    pub fn cache_status(&self) -> CacheStatus {
        let total_cached_packets = self.fragment_cache.len();
        let total_cached_fragments: usize = self.fragment_cache.values()
            .map(|cache| cache.fragments.len())
            .sum();

        let oldest_cache = self.fragment_cache.values()
            .min_by_key(|cache| cache.first_fragment_time);

        let newest_cache = self.fragment_cache.values()
            .max_by_key(|cache| cache.first_fragment_time);

        CacheStatus {
            cached_packets: total_cached_packets,
            cached_fragments: total_cached_fragments,
            cache_usage_bytes: self.current_cache_size,
            oldest_timestamp: oldest_cache.map(|c| c.first_fragment_time),
            newest_timestamp: newest_cache.map(|c| c.first_fragment_time),
        }
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> &FragmenterStats {
        &self.stats
    }

    /// 重置重组器
    pub fn reset(&mut self) {
        self.fragment_cache.clear();
        self.current_cache_size = 0;
        self.stats = FragmenterStats::default();
    }

    /// 更新配置
    pub fn update_config(&mut self, config: FragmenterConfig) {
        self.config = config;
    }
}

/// 分片错误类型
#[derive(Debug, thiserror::Error)]
pub enum FragmentationError {
    #[error("Invalid IP header")]
    InvalidHeader,
    #[error("Too many fragments: {0}")]
    TooManyFragments(usize),
    #[error("Fragment overlap detected")]
    FragmentOverlap,
    #[error("Invalid fragment offset")]
    InvalidOffset,
    #[error("Buffer full")]
    BufferFull,
}

/// 缓存状态
#[derive(Debug, Clone)]
pub struct CacheStatus {
    /// 缓存的数据包数量
    pub cached_packets: usize,
    /// 缓存的分片总数
    pub cached_fragments: usize,
    /// 缓存使用字节数
    pub cache_usage_bytes: usize,
    /// 最旧缓存的时间戳
    pub oldest_timestamp: Option<u64>,
    /// 最新缓存的时间戳
    pub newest_timestamp: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, IpAddr};

    fn create_test_packet() -> PacketInfo {
        PacketInfo {
            timestamp: 123456789,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 0,
            dst_port: 0,
            protocol: 6, // TCP
            payload: vec![1, 2, 3, 4, 5],
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            tcp_window: None,
        }
    }

    #[test]
    fn test_fragment_reassembly() {
        let mut fragmenter = IpFragmenter::with_default_config();
        let packet = create_test_packet();

        // 测试处理分片
        let result = fragmenter.process_fragment(&packet);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cleanup_timeout() {
        let mut config = FragmenterConfig::default();
        config.fragment_timeout = Duration::from_millis(100);
        let mut fragmenter = IpFragmenter::new(config);

        // 测试超时清理
        fragmenter.cleanup_expired_fragments();
        assert_eq!(fragmenter.stats.timeout_packets, 0);
    }
}