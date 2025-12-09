//! TCP流管理器
//!
//! 负责管理所有TCP流的创建、查找、更新和删除

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use crate::types::flow::{FlowKey, FlowDirection};
use crate::types::stream::{TcpStream, TcpState, StreamEvent, StreamEventRecord};
use crate::types::PacketInfo;

/// 流管理器配置
#[derive(Debug, Clone)]
pub struct StreamManagerConfig {
    /// 流超时时间（秒）
    pub stream_timeout: Duration,
    /// 最大并发流数
    pub max_streams: usize,
    /// 是否启用流事件记录
    pub enable_event_logging: bool,
    /// 每个流最大事件记录数
    pub max_events_per_stream: usize,
    /// 清理间隔
    pub cleanup_interval: Duration,
    /// 是否启用SYN后RST-888检测
    pub syn_rst_888: bool,
    /// 是否启用三次握手ACK后RST-888检测
    pub handshake_ack_rst_888: bool,
}

impl Default for StreamManagerConfig {
    fn default() -> Self {
        Self {
            stream_timeout: Duration::from_secs(300), // 5分钟
            max_streams: 100000,
            enable_event_logging: true,
            max_events_per_stream: 1000,
            cleanup_interval: Duration::from_secs(60), // 1分钟
            syn_rst_888: false,
            handshake_ack_rst_888: false,
        }
    }
}

/// 流管理器
///
/// 管理所有TCP流的生命周期，包括创建、查找、更新和删除
pub struct StreamManager {
    /// 流表，使用FlowKey作为键
    streams: HashMap<FlowKey, TcpStream>,
    /// 配置
    config: StreamManagerConfig,
    /// 最后清理时间
    last_cleanup: Instant,
    /// 流统计信息
    stats: StreamManagerStats,
}

/// 流管理器统计信息
#[derive(Debug, Clone, Default)]
pub struct StreamManagerStats {
    /// 当前活跃流数
    pub active_streams: usize,
    /// 总创建流数
    pub total_streams_created: u64,
    /// 总关闭流数
    pub total_streams_closed: u64,
    /// 超时关闭的流数
    pub timeout_streams: u64,
    /// 重置的流数
    pub reset_streams: u64,
    /// 最大并发流数
    pub peak_concurrent_streams: usize,
}

impl StreamManager {
    /// 创建新的流管理器
    pub fn new(config: StreamManagerConfig) -> Self {
        Self {
            streams: HashMap::new(),
            config,
            last_cleanup: Instant::now(),
            stats: StreamManagerStats::default(),
        }
    }

    /// 使用默认配置创建流管理器
    pub fn with_default_config() -> Self {
        Self::new(StreamManagerConfig::default())
    }

    /// 处理数据包
    pub fn process_packet(&mut self, packet: &PacketInfo) -> FlowKey {
        // 检查是否需要清理过期流
        if self.last_cleanup.elapsed() >= self.config.cleanup_interval {
            self.cleanup_expired_streams();
        }

        // 创建流键值
        let flow_key = FlowKey::new(
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
        );

        // 检查流是否已存在
        let flow_key = if let Some((existing_key, _)) = self.streams.get_key_value(&flow_key) {
            existing_key.clone() // 返回已存在的 FlowKey，保持方向信息
        } else {
            flow_key // 使用新创建的 FlowKey
        };

        // 获取或创建流
        if !self.streams.contains_key(&flow_key) {
            // 检查是否超过最大流数限制
            if self.streams.len() >= self.config.max_streams {
                // 强制清理最旧的流
                self.force_cleanup_oldest_stream();
            }

            // 创建新流
            let mut stream = TcpStream::new(flow_key.clone());

            // 记录流创建事件
            if self.config.enable_event_logging {
                stream.add_event(StreamEventRecord::new(
                    packet.timestamp,
                    StreamEvent::StreamCreated,
                    format!("Stream created: {}", flow_key),
                ));
            }

            // 更新统计信息
            self.stats.total_streams_created += 1;
            self.stats.active_streams = self.streams.len() + 1;
            if self.stats.active_streams > self.stats.peak_concurrent_streams {
                self.stats.peak_concurrent_streams = self.stats.active_streams;
            }

            self.streams.insert(flow_key.clone(), stream);
        }

        // 更新流信息
        self.update_stream(&flow_key, packet);

        flow_key
    }

    /// 更新流信息
    fn update_stream(&mut self, flow_key: &FlowKey, packet: &PacketInfo) -> FlowKey {
        // 判断流方向
        let direction = flow_key.get_direction(&packet.src_ip, packet.src_port);
        let is_client = matches!(direction, FlowDirection::ClientToServer);

        // 一次性获取流的可变引用并更新所有信息
        if let Some(stream) = self.streams.get_mut(flow_key) {
            // 更新序列号信息
            if let (Some(seq), Some(ack)) = (packet.tcp_seq, packet.tcp_ack) {
                stream.update_sequence(seq, ack, is_client, packet.payload.len() as u32);
            }

            // 检查流是否已被 RST 终止
            let should_ignore_stats = stream.rst_time.is_some() &&
                packet.timestamp > stream.rst_time.unwrap_or(0);

            // 更新连接信息
            stream.connection.update_activity(packet.timestamp);

            // 更新TCP状态
            let flags = packet.tcp_flags.unwrap_or(0);
            let syn_flag = (flags & 0x02) != 0;
            let ack_flag = (flags & 0x10) != 0;
            let fin_flag = (flags & 0x01) != 0;
            let rst_flag = (flags & 0x04) != 0;

            // 根据配置检测RST-888（不需要同时进行）
            if self.config.syn_rst_888 {
                // syn-rst-888: 检测SYN后的RST-ACK
                stream.detect_rst_888_after_syn(&packet);
            } else if self.config.handshake_ack_rst_888 {
                // handshake-ack-rst-888: 检测三次握手ACK后的RST（非RST-ACK）
                stream.detect_rst_after_handshake_ack(&packet);
            }

            // 如果是 RST 报文，使用专门的 RST 处理方法
            if rst_flag {
                if stream.handle_rst(&packet) {
                    // RST 报文有效，已被处理，但仍然更新统计信息（最后一个包）
                    stream.stats.update(packet.payload.len(), direction, packet.timestamp);
                    return flow_key.clone();
                } else {
                    // RST 报文无效，忽略但继续处理
                }
            }

            // 只有在流未被 RST 终止时才更新统计信息
            if !should_ignore_stats {
                stream.stats.update(packet.payload.len(), direction, packet.timestamp);
            }

            // TCP状态机转换（不包括 RST）
            let new_state = match (stream.state, syn_flag, ack_flag, fin_flag, is_client) {
                // CLOSED状态
                (TcpState::Closed, true, false, false, true) => TcpState::SynSent,  // SYN from client
                (TcpState::Closed, true, false, false, false) => TcpState::SynReceived,  // SYN from server

                // SYN_SENT状态（客户端）
                (TcpState::SynSent, _, true, _, _) => TcpState::Established,

                // SYN_RECEIVED状态（服务器）
                (TcpState::SynReceived, _, true, _, _) => TcpState::Established,

                // ESTABLISHED状态
                (TcpState::Established, _, _, true, _) => {
                    if is_client {
                        TcpState::FinWait1
                    } else {
                        TcpState::CloseWait
                    }
                }

                // FIN_WAIT_1状态
                (TcpState::FinWait1, _, true, _, true) => TcpState::FinWait2,
                (TcpState::FinWait1, _, true, _, _) => TcpState::Closing,

                // FIN_WAIT_2状态
                (TcpState::FinWait2, _, _, _, _) => TcpState::TimeWait,

                // CLOSE_WAIT状态
                (TcpState::CloseWait, _, _, _, _) => TcpState::LastAck,

                // CLOSING状态
                (TcpState::Closing, _, true, _, _) => TcpState::TimeWait,

                // LAST_ACK状态
                (TcpState::LastAck, _, true, _, _) => TcpState::Closed,

                // TIME_WAIT状态（保持原状态，等待超时）
                (TcpState::TimeWait, _, _, _, _) => TcpState::TimeWait,

                // 其他情况保持原状态
                (state, _, _, _, _) => state,
            };

            // 更新握手状态
            if syn_flag && !ack_flag {
                // SYN包
                if is_client {
                    stream.connection.handshake.client_syn = true;
                    // 重置SYN后的计数器
                    stream.packets_since_syn = 0;
                } else {
                    // 服务器SYN（这种情况较少见）
                }
            } else if syn_flag && ack_flag {
                // SYN-ACK包
                stream.connection.handshake.server_syn_ack = true;
                // SYN后的计数器递增（SYN-ACK是SYN后的第一个包）
                stream.packets_since_syn += 1;
            } else if ack_flag && !syn_flag && !fin_flag && !rst_flag {
                // ACK包（可能是握手完成）
                if stream.connection.handshake.client_syn && stream.connection.handshake.server_syn_ack && !stream.connection.handshake.client_ack {
                    // 这是三次握手的ACK包
                    stream.connection.handshake.client_ack = true;
                    // 重置三次握手ACK后的计数器并递增（这个ACK本身是第一个包）
                    stream.packets_since_handshake_ack = 1;
                    // SYN后的计数器递增（ACK是第二个包）
                    stream.packets_since_syn += 1;
                } else {
                    // 普通ACK包
                    stream.packets_since_syn += 1;
                    if stream.connection.handshake.is_complete() {
                        stream.packets_since_handshake_ack += 1;
                    }
                }
            } else {
                // 其他数据包
                stream.packets_since_syn += 1;
                if stream.connection.handshake.is_complete() {
                    stream.packets_since_handshake_ack += 1;
                }
            }

            // 如果状态改变，更新状态
            if new_state != stream.state {
                stream.update_state(new_state, packet.timestamp);
            }

            // 记录事件
            if self.config.enable_event_logging {
                // 检测重传
                if let (Some(last_ack), Some(current_ack)) = (if is_client { stream.client_ack } else { stream.server_ack }, packet.tcp_ack) {
                    if current_ack <= last_ack && !packet.payload.is_empty() {
                        stream.add_event(StreamEventRecord::new(
                            packet.timestamp,
                            StreamEvent::Retransmission,
                            format!("Retransmission detected: ACK {} <= {}", current_ack, last_ack),
                        ).with_sequence(packet.tcp_seq.unwrap_or(0)));
                        stream.connection.retransmission_count += 1;
                    }
                }

                // 检测窗口更新
                if let Some(window) = packet.tcp_window {
                    if window > 0 {
                        stream.add_event(StreamEventRecord::new(
                            packet.timestamp,
                            StreamEvent::WindowUpdate,
                            format!("Window updated: {}", window),
                        ));
                    }
                }

                // 检测流重置
                if let Some(flags) = packet.tcp_flags {
                    if flags & 0x04 != 0 {
                        stream.add_event(StreamEventRecord::new(
                            packet.timestamp,
                            StreamEvent::StreamReset,
                            "Stream reset by RST flag".to_string(),
                        ));
                        stream.connection.close.reset = true;
                        stream.connection.close.update(packet.timestamp);
                    }
                }
            }
        }

        flow_key.clone()
    }

    
    /// 清理过期的流
    pub fn cleanup_expired_streams(&mut self) {
        let timeout_micros = self.config.stream_timeout.as_micros() as u64;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;

        let mut to_remove = Vec::new();

        for (flow_key, stream) in &self.streams {
            // 检查流是否超时
            if let Some(last_activity) = stream.connection.last_activity {
                if current_time - last_activity > timeout_micros {
                    to_remove.push(flow_key.clone());
                }
            } else {
                // 没有活动记录的流也移除
                to_remove.push(flow_key.clone());
            }
        }

        // 移除过期流
        for flow_key in to_remove {
            if let Some(mut stream) = self.streams.remove(&flow_key) {
                // 记录超时事件
                if self.config.enable_event_logging {
                    stream.add_event(StreamEventRecord::new(
                        current_time,
                        StreamEvent::Timeout,
                        "Stream expired due to inactivity".to_string(),
                    ));
                }
                self.stats.timeout_streams += 1;
                self.stats.total_streams_closed += 1;
            }
        }

        // 更新统计信息
        self.stats.active_streams = self.streams.len();
        self.last_cleanup = Instant::now();
    }

    /// 强制清理最旧的流
    fn force_cleanup_oldest_stream(&mut self) {
        if let Some((oldest_key, _)) = self.streams.iter()
            .min_by_key(|(_, stream)| stream.connection.last_activity.unwrap_or(0)) {
            let oldest_key = oldest_key.clone();
            self.streams.remove(&oldest_key);
            self.stats.total_streams_closed += 1;
        }
    }

    /// 查找流
    pub fn find_stream(&self, flow_key: &FlowKey) -> Option<&TcpStream> {
        self.streams.get(flow_key)
    }

    /// 查找流（可变引用）
    pub fn find_stream_mut(&mut self, flow_key: &FlowKey) -> Option<&mut TcpStream> {
        self.streams.get_mut(flow_key)
    }

    /// 根据五元组查找流
    pub fn find_stream_by_tuple(&self, src_ip: IpAddr, dst_ip: IpAddr,
                               src_port: u16, dst_port: u16, protocol: u8) -> Option<&TcpStream> {
        let flow_key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, protocol);
        self.find_stream(&flow_key)
    }

    /// 获取所有活跃流
    pub fn get_active_streams(&self) -> impl Iterator<Item = &TcpStream> {
        self.streams.values().filter(|s| s.connection.is_active())
    }

    /// 获取所有流
    pub fn get_all_streams(&self) -> impl Iterator<Item = &TcpStream> {
        self.streams.values()
    }

    /// 获取流数量
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// 关闭指定的流
    pub fn close_stream(&mut self, flow_key: &FlowKey) -> Option<TcpStream> {
        if let Some(mut stream) = self.streams.remove(flow_key) {
            stream.update_state(TcpState::Closed,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_micros() as u64
            );
            self.stats.total_streams_closed += 1;
            self.stats.active_streams = self.streams.len();
            Some(stream)
        } else {
            None
        }
    }

    /// 插入一个流到管理器中（用于从其他管理器复制流）
    pub fn insert_stream(&mut self, stream: TcpStream) {
        let flow_key = stream.flow_key.clone();
        self.streams.insert(flow_key, stream);
    }

    /// 清空所有流
    pub fn clear_all_streams(&mut self) {
        self.streams.clear();
        self.stats.active_streams = 0;
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> &StreamManagerStats {
        &self.stats
    }

    /// 重置统计信息
    pub fn reset_stats(&mut self) {
        self.stats = StreamManagerStats::default();
        self.stats.active_streams = self.streams.len();
    }

    /// 更新配置
    pub fn update_config(&mut self, config: StreamManagerConfig) {
        self.config = config;
    }

    /// 获取配置
    pub fn get_config(&self) -> &StreamManagerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PacketInfo;
    use std::net::{Ipv4Addr, IpAddr};

    fn create_test_packet(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16) -> PacketInfo {
        PacketInfo {
            timestamp: 123456789,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: 6, // TCP
            payload: vec![1, 2, 3, 4],
            tcp_seq: Some(1000),
            tcp_ack: Some(2000),
            tcp_flags: Some(0x10), // ACK
            tcp_window: Some(8192),
        }
    }

    #[test]
    fn test_stream_creation() {
        let mut manager = StreamManager::with_default_config();

        let packet = create_test_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            8080,
            80,
        );

        manager.process_packet(&packet);

        assert_eq!(manager.stream_count(), 1);
        assert_eq!(manager.stats.total_streams_created, 1);
    }

    #[test]
    fn test_stream_lookup() {
        let mut manager = StreamManager::with_default_config();

        let packet = create_test_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            8080,
            80,
        );

        manager.process_packet(&packet);

        let flow_key = FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            8080,
            80,
            6,
        );

        assert!(manager.find_stream(&flow_key).is_some());
    }

    #[test]
    fn test_bidirectional_flow() {
        let mut manager = StreamManager::with_default_config();

        // 客户端到服务器的数据包
        let packet1 = create_test_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            8080,
            80,
        );

        // 服务器到客户端的数据包
        let packet2 = create_test_packet(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
            8080,
        );

        manager.process_packet(&packet1);
        manager.process_packet(&packet2);

        // 应该只有一个流
        assert_eq!(manager.stream_count(), 1);
    }
}