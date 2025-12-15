//! TCP重组器
//!
//! 负责处理TCP分段的重组，包括乱序处理、重传检测等

use std::collections::BTreeMap;
use std::cmp::{min, max};
use std::time::{Duration, Instant};
use crate::types::PacketInfo;

/// TCP重组器配置
#[derive(Debug, Clone)]
pub struct ReassemblerConfig {
    /// 最大缓冲区大小（字节）
    pub max_buffer_size: usize,
    /// 分段超时时间（秒）
    pub segment_timeout: Duration,
    /// 最大乱序窗口大小（字节）
    pub max_out_of_order_window: u32,
    /// 是否启用快速重组
    pub enable_fast_reassembly: bool,
    /// 是否检测重复数据
    pub detect_duplicates: bool,
    /// 最大重叠处理次数
    pub max_overlap_count: u32,
}

impl Default for ReassemblerConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 16 * 1024 * 1024, // 16MB
            segment_timeout: Duration::from_secs(30),
            max_out_of_order_window: 64 * 1024, // 64KB
            enable_fast_reassembly: true,
            detect_duplicates: true,
            max_overlap_count: 10,
        }
    }
}

/// TCP分段信息
#[derive(Debug, Clone)]
pub struct TcpSegment {
    /// 序列号
    pub seq: u32,
    /// 数据内容
    pub data: Vec<u8>,
    /// 接收时间戳
    pub timestamp: u64,
    /// 重传次数
    pub retransmission_count: u32,
    /// 是否被确认
    pub acked: bool,
    /// 分段长度
    pub len: u32,
    /// 结束序列号（不包含）
    pub end_seq: u32,
}

impl TcpSegment {
    /// 创建新的TCP分段
    pub fn new(seq: u32, data: Vec<u8>, timestamp: u64) -> Self {
        let len = data.len() as u32;
        Self {
            seq,
            data,
            timestamp,
            retransmission_count: 0,
            acked: false,
            len,
            end_seq: seq.wrapping_add(len),
        }
    }

    /// 检查是否与给定范围重叠
    pub fn overlaps(&self, start: u32, end: u32) -> bool {
        self.seq < end && self.end_seq > start
    }

    /// 获取与给定范围重叠的部分
    pub fn get_overlap(&self, start: u32, end: u32) -> Option<(u32, u32)> {
        let overlap_start = max(self.seq, start);
        let overlap_end = min(self.end_seq, end);

        if overlap_start < overlap_end {
            Some((overlap_start, overlap_end))
        } else {
            None
        }
    }

    /// 截取分段中指定范围的数据
    pub fn slice(&self, start: u32, end: u32) -> Option<Vec<u8>> {
        if start < self.seq || end > self.end_seq || start >= end {
            return None;
        }

        let offset = (start - self.seq) as usize;
        let len = (end - start) as usize;

        if offset + len <= self.data.len() {
            Some(self.data[offset..offset + len].to_vec())
        } else {
            None
        }
    }

    /// 检查是否是重复分段
    pub fn is_duplicate(&self, other: &TcpSegment) -> bool {
        self.seq == other.seq && self.end_seq == other.end_seq && self.data == other.data
    }
}

/// 重组结果
#[derive(Debug, Clone)]
pub struct ReassemblyResult {
    /// 重组后的数据
    pub data: Vec<u8>,
    /// 起始序列号
    pub start_seq: u32,
    /// 结束序列号
    pub end_seq: u32,
    /// 包含的分段数
    pub segment_count: usize,
    /// 是否有数据间隙
    pub has_gaps: bool,
    /// 重组耗时（微秒）
    pub assembly_time_us: u64,
}

/// TCP重组器
///
/// 处理TCP分段的接收、缓存和重组
pub struct TcpReassembler {
    /// 配置
    config: ReassemblerConfig,
    /// 分段缓冲区，按序列号排序
    segments: BTreeMap<u32, TcpSegment>,
    /// 下一个期望的序列号
    next_seq: u32,
    /// 最大接收序列号（用于窗口管理）
    max_seq: u32,
    /// 最后重组时间
    last_assembly: Instant,
    /// 统计信息
    stats: ReassemblerStats,
    /// 接收窗口大小
    window_size: u32,
    /// 重复数据检测
    seen_data: BTreeMap<u32, Vec<u8>>, // 简化的重复检测
}

/// 重组器统计信息
#[derive(Debug, Clone, Default)]
pub struct ReassemblerStats {
    /// 接收的分段总数
    pub total_segments: u64,
    /// 重组的数据总数
    pub total_bytes_reassembled: u64,
    /// 丢弃的分段数
    pub discarded_segments: u64,
    /// 重传分段数
    pub retransmitted_segments: u64,
    /// 重复分段数
    pub duplicate_segments: u64,
    /// 乱序分段数
    pub out_of_order_segments: u64,
    /// 重叠分段数
    pub overlapping_segments: u64,
    /// 重组操作次数
    pub assembly_operations: u64,
    /// 平均重组时间（微秒）
    pub avg_assembly_time_us: f64,
    /// 缓冲区使用峰值
    pub peak_buffer_usage: usize,
}

impl TcpReassembler {
    /// 创建新的TCP重组器
    pub fn new(config: ReassemblerConfig) -> Self {
        Self {
            config,
            segments: BTreeMap::new(),
            next_seq: 0,
            max_seq: 0,
            last_assembly: Instant::now(),
            stats: ReassemblerStats::default(),
            window_size: 65535, // 默认TCP窗口大小
            seen_data: BTreeMap::new(),
        }
    }

    /// 使用默认配置创建TCP重组器
    pub fn with_default_config() -> Self {
        Self::new(ReassemblerConfig::default())
    }

    /// 设置初始序列号
    pub fn set_initial_seq(&mut self, seq: u32) {
        self.next_seq = seq;
        self.max_seq = seq;
    }

    /// 设置接收窗口大小
    pub fn set_window_size(&mut self, window_size: u32) {
        self.window_size = window_size;
    }

    /// 处理TCP分段
    pub fn process_segment(&mut self, packet: &PacketInfo) -> Result<Option<ReassemblyResult>, ReassemblyError> {
        let seq = packet.tcp_seq.ok_or(ReassemblyError::MissingSequenceNumber)?;
        let data = &packet.payload;

        if data.is_empty() {
            return Ok(None); // 忽略纯ACK包
        }

        // 检测重复（在窗口检查之前）
        if self.config.detect_duplicates {
            // 首先检查是否已经在缓冲区中
            if let Some(existing) = self.segments.get(&seq) {
                if existing.data == *data {
                    // 创建分段以检查是否为重传
                    let segment = TcpSegment::new(seq, data.to_vec(), packet.timestamp);
                    if self.is_retransmission(&segment) {
                        self.stats.retransmitted_segments += 1;
                    }
                    self.stats.duplicate_segments += 1;
                    return Ok(None);
                }
            }

            // 检查是否是已经重组过的数据
            if seq < self.next_seq && seq + data.len() as u32 <= self.next_seq {
                // 这个分段已经完全在重组的范围内
                // 创建分段以检查是否为重传
                let segment = TcpSegment::new(seq, data.to_vec(), packet.timestamp);
                if self.is_retransmission(&segment) {
                    self.stats.retransmitted_segments += 1;
                }
                self.stats.duplicate_segments += 1;
                return Ok(None);
            }
        }

        // 更新最大序列号
        self.max_seq = max(self.max_seq, seq + data.len() as u32);

        // 检查窗口
        if !self.is_in_window(seq, data.len() as u32) {
            self.stats.discarded_segments += 1;
            return Err(ReassemblyError::OutsideWindow(seq));
        }

        // 创建分段
        let segment = TcpSegment::new(seq, data.clone(), packet.timestamp);

        // 检查重传
        let is_retransmission = self.is_retransmission(&segment);
        if is_retransmission {
            self.stats.retransmitted_segments += 1;
        }

        // 插入分段
        self.insert_segment(segment, is_retransmission)?;

        // 尝试重组
        self.try_reassemble()
    }

    /// 检查序列号是否在窗口内
    fn is_in_window(&self, seq: u32, len: u32) -> bool {
        let window_end = self.next_seq.wrapping_add(self.window_size);

        // 处理序列号回绕
        if self.next_seq <= window_end {
            seq >= self.next_seq && seq + len <= window_end
        } else {
            seq >= self.next_seq || seq + len <= window_end
        }
    }

    /// 检查是否是重复数据
    #[allow(dead_code)]  // 暂未使用，保留用于未来的优化
    fn is_duplicate(&self, seq: u32, data: &[u8]) -> bool {
        // 检查是否已经在重组缓冲区中
        if let Some(existing) = self.segments.get(&seq) {
            return existing.data == data;
        }

        // 检查是否已经重组过
        if let (Some(start), Some(end)) = (self.segments.first_key_value(), self.segments.last_key_value()) {
            if seq >= *start.0 && seq + data.len() as u32 <= end.1.end_seq {
                // 数据已经在期望的范围内
                return true;
            }
        }

        false
    }

    /// 检查是否是重传
    fn is_retransmission(&self, segment: &TcpSegment) -> bool {
        // 检查序列号是否小于下一个期望序列号
        if segment.seq < self.next_seq {
            return true;
        }

        // 检查是否有相同的分段
        for (_, existing) in &self.segments {
            if existing.is_duplicate(segment) {
                return true;
            }
        }

        false
    }

    /// 插入分段到缓冲区
    fn insert_segment(&mut self, segment: TcpSegment, is_retransmission: bool) -> Result<(), ReassemblyError> {
        // 检查缓冲区大小
        let current_size: usize = self.segments.values()
            .map(|s| s.data.len())
            .sum();

        if current_size + segment.data.len() > self.config.max_buffer_size {
            // 清理旧分段
            self.cleanup_old_segments();

            // 再次检查
            let new_size: usize = self.segments.values()
                .map(|s| s.data.len())
                .sum();

            if new_size + segment.data.len() > self.config.max_buffer_size {
                self.stats.discarded_segments += 1;
                return Err(ReassemblyError::BufferFull);
            }
        }

        // 检测重叠
        let segment_seq = segment.seq;
        self.handle_overlaps(&segment)?;

        // 插入分段
        self.segments.insert(segment.seq, segment);

        // 更新统计
        self.stats.total_segments += 1;
        if !is_retransmission && segment_seq != self.next_seq {
            self.stats.out_of_order_segments += 1;
        }

        // 更新缓冲区使用峰值
        let current_usage = self.segments.len();
        if current_usage > self.stats.peak_buffer_usage {
            self.stats.peak_buffer_usage = current_usage;
        }

        Ok(())
    }

    /// 处理重叠分段
    fn handle_overlaps(&mut self, new_segment: &TcpSegment) -> Result<(), ReassemblyError> {
        let mut overlapping_keys = Vec::new();
        let mut overlap_count = 0;

        for (seq, existing) in &self.segments {
            if new_segment.overlaps(*seq, existing.end_seq) {
                overlapping_keys.push(*seq);
                overlap_count += 1;
            }
        }

        if overlap_count > self.config.max_overlap_count as usize {
            return Err(ReassemblyError::TooManyOverlaps(overlap_count));
        }

        // 处理重叠（这里简化为移除旧分段）
        for key in overlapping_keys {
            self.segments.remove(&key);
            self.stats.overlapping_segments += 1;
        }

        Ok(())
    }

    /// 尝试重组数据
    fn try_reassemble(&mut self) -> Result<Option<ReassemblyResult>, ReassemblyError> {
        let start_time = Instant::now();
        let mut assembled_data = Vec::new();
        let mut segment_count = 0;
        let mut has_gaps = false;
        let start_seq = self.next_seq;

        // 按序组装数据
        while let Some(segment) = self.segments.get(&self.next_seq) {
            if segment.seq == self.next_seq {
                let segment_len = segment.len;
                assembled_data.extend_from_slice(&segment.data);
                self.next_seq = segment.end_seq;
                segment_count += 1;

                // 移除已重组的分段
                self.segments.remove(&(self.next_seq - segment_len));
            } else {
                // 有间隙
                has_gaps = true;

                // 检查是否有下一个分段
                if let Some((next_key, _)) = self.segments.range(self.next_seq..).next() {
                    // 检查是否超出乱序窗口
                    if next_key > &self.next_seq.wrapping_add(self.config.max_out_of_order_window) {
                        break;
                    }

                    // 尝试填充部分数据（快速重组模式）
                    if self.config.enable_fast_reassembly && !self.segments.is_empty() {
                        if next_key > &self.next_seq {
                            // 检查是否有足够的数据填充间隙
                            self.fill_gaps();
                        }
                    }
                }

                break;
            }
        }

        let assembly_time = start_time.elapsed().as_micros() as u64;

        // 更新统计
        if segment_count > 0 {
            self.stats.total_bytes_reassembled += assembled_data.len() as u64;
            self.stats.assembly_operations += 1;

            // 更新平均重组时间
            let total_time = self.stats.avg_assembly_time_us * (self.stats.assembly_operations - 1) as f64;
            self.stats.avg_assembly_time_us = (total_time + assembly_time as f64) / self.stats.assembly_operations as f64;

            self.last_assembly = Instant::now();

            return Ok(Some(ReassemblyResult {
                data: assembled_data,
                start_seq,
                end_seq: self.next_seq,
                segment_count,
                has_gaps,
                assembly_time_us: assembly_time,
            }));
        }

        Ok(None)
    }

    /// 填充数据间隙（使用零或保留）
    fn fill_gaps(&mut self) {
        // 在实际实现中，这里可以更智能地处理间隙
        // 例如：等待一段时间、发送选择性ACK等
    }

    /// 清理过期的分段
    fn cleanup_old_segments(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let timeout_micros = self.config.segment_timeout.as_micros() as u64;

        let mut to_remove = Vec::new();

        for (seq, segment) in &self.segments {
            if now - segment.timestamp > timeout_micros {
                to_remove.push(*seq);
            }
        }

        for key in to_remove {
            self.segments.remove(&key);
            self.stats.discarded_segments += 1;
        }
    }

    /// 强制重组所有可用数据
    pub fn force_reassemble(&mut self) -> Option<ReassemblyResult> {
        let start_time = Instant::now();
        let mut assembled_data = Vec::new();
        let mut segment_count = 0;
        let start_seq = self.next_seq;

        // 收集所有分段数据
        let mut all_segments: Vec<_> = self.segments.values().cloned().collect();
        all_segments.sort_by_key(|s| s.seq);

        let mut current_seq = self.next_seq;

        for segment in all_segments {
            // 处理间隙
            if segment.seq > current_seq {
                // 填充间隙（使用零）
                let gap_len = segment.seq - current_seq;
                assembled_data.extend(vec![0; gap_len as usize]);
            }

            assembled_data.extend_from_slice(&segment.data);
            current_seq = segment.end_seq;
            segment_count += 1;
        }

        let assembly_time = start_time.elapsed().as_micros() as u64;

        if !assembled_data.is_empty() {
            self.next_seq = current_seq;
            self.segments.clear();

            Some(ReassemblyResult {
                data: assembled_data,
                start_seq,
                end_seq: self.next_seq,
                segment_count,
                has_gaps: true, // 强制重组可能有间隙
                assembly_time_us: assembly_time,
            })
        } else {
            None
        }
    }

    /// 获取缓冲区状态
    pub fn buffer_status(&self) -> BufferStatus {
        let total_bytes: usize = self.segments.values()
            .map(|s| s.data.len())
            .sum();

        let oldest_segment = self.segments.values()
            .min_by_key(|s| s.timestamp);

        let newest_segment = self.segments.values()
            .max_by_key(|s| s.timestamp);

        BufferStatus {
            segment_count: self.segments.len(),
            total_bytes,
            oldest_timestamp: oldest_segment.map(|s| s.timestamp),
            newest_timestamp: newest_segment.map(|s| s.timestamp),
            next_expected_seq: self.next_seq,
            max_received_seq: self.max_seq,
            window_size: self.window_size,
        }
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> &ReassemblerStats {
        &self.stats
    }

    /// 重置重组器
    pub fn reset(&mut self) {
        self.segments.clear();
        self.next_seq = 0;
        self.max_seq = 0;
        self.seen_data.clear();
        self.stats = ReassemblerStats::default();
    }

    /// 更新配置
    pub fn update_config(&mut self, config: ReassemblerConfig) {
        self.config = config;
    }
}

/// 重组错误类型
#[derive(Debug, thiserror::Error)]
pub enum ReassemblyError {
    #[error("Missing sequence number in packet")]
    MissingSequenceNumber,
    #[error("Segment outside window (seq: {0})")]
    OutsideWindow(u32),
    #[error("Buffer full")]
    BufferFull,
    #[error("Too many overlapping segments: {0}")]
    TooManyOverlaps(usize),
    #[error("Invalid segment length")]
    InvalidLength,
}

/// 缓冲区状态
#[derive(Debug, Clone)]
pub struct BufferStatus {
    /// 分段数量
    pub segment_count: usize,
    /// 总字节数
    pub total_bytes: usize,
    /// 最旧分段时间戳
    pub oldest_timestamp: Option<u64>,
    /// 最新分段时间戳
    pub newest_timestamp: Option<u64>,
    /// 下一个期望序列号
    pub next_expected_seq: u32,
    /// 最大接收序列号
    pub max_received_seq: u32,
    /// 窗口大小
    pub window_size: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PacketInfo;
    use std::net::{Ipv4Addr, IpAddr};

    fn create_test_segment(seq: u32, data: Vec<u8>) -> PacketInfo {
        PacketInfo {
            timestamp: 123456789,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            src_port: 8080,
            dst_port: 80,
            protocol: 6,
            payload: data,
            tcp_seq: Some(seq),
            tcp_ack: Some(0),
            tcp_flags: Some(0x18), // PSH+ACK
            tcp_window: Some(8192),
        }
    }

    #[test]
    fn test_sequential_reassembly() {
        let mut reassembler = TcpReassembler::with_default_config();
        reassembler.set_initial_seq(1000);

        // 发送有序分段
        let seg1 = create_test_segment(1000, vec![1, 2, 3]);
        let seg2 = create_test_segment(1003, vec![4, 5, 6]);
        let seg3 = create_test_segment(1006, vec![7, 8, 9]);

        let result1 = reassembler.process_segment(&seg1).unwrap();
        assert!(result1.is_some());
        assert_eq!(result1.unwrap().data, vec![1, 2, 3]);

        let result2 = reassembler.process_segment(&seg2).unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().data, vec![4, 5, 6]);

        let result3 = reassembler.process_segment(&seg3).unwrap();
        assert!(result3.is_some());
        assert_eq!(result3.unwrap().data, vec![7, 8, 9]);
    }

    #[test]
    fn test_out_of_order_reassembly() {
        let mut reassembler = TcpReassembler::with_default_config();
        reassembler.set_initial_seq(1000);

        // 发送乱序分段
        let seg2 = create_test_segment(1003, vec![4, 5, 6]);
        let seg1 = create_test_segment(1000, vec![1, 2, 3]);
        let _seg3 = create_test_segment(1006, vec![7, 8, 9]);

        // 先发送seg2，应该缓冲
        let result2 = reassembler.process_segment(&seg2).unwrap();
        assert!(result2.is_none());

        // 发送seg1，应该重组seg1和seg2
        let result1 = reassembler.process_segment(&seg1).unwrap();
        assert!(result1.is_some());
        assert_eq!(result1.unwrap().data, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_duplicate_detection() {
        let mut config = ReassemblerConfig::default();
        config.detect_duplicates = true;
        let mut reassembler = TcpReassembler::new(config);
        reassembler.set_window_size(65535); // 使用大窗口避免超出问题
        reassembler.set_initial_seq(1000);

        let seg1 = create_test_segment(1000, vec![1, 2, 3]);

        // 发送两次相同的分段
        let result1 = reassembler.process_segment(&seg1);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_some());

        // 第二次发送相同分段应该被识别为重复
        let result2 = reassembler.process_segment(&seg1);
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_none()); // 重复分段应该被忽略

        assert_eq!(reassembler.stats.duplicate_segments, 1);
    }

    #[test]
    fn test_retransmission_detection() {
        let mut config = ReassemblerConfig::default();
        config.detect_duplicates = true;
        let mut reassembler = TcpReassembler::new(config);
        reassembler.set_window_size(65535); // 使用大窗口避免超出问题
        reassembler.set_initial_seq(1000);

        // 发送seg1并推进next_seq
        let seg1 = create_test_segment(1000, vec![1, 2, 3]);
        let result1 = reassembler.process_segment(&seg1);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_some());

        // 重新发送seg1（重传）
        let seg1_retrans = create_test_segment(1000, vec![1, 2, 3]);
        let result2 = reassembler.process_segment(&seg1_retrans);
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_none()); // 重传应该被忽略

        assert_eq!(reassembler.stats.retransmitted_segments, 1);
    }
}