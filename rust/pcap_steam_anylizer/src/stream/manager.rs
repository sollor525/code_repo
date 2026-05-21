//! TCP流管理器
//!
//! 负责管理所有TCP流的创建、查找、更新和删除

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use crate::types::flow::{FlowKey, FlowDirection};
use crate::types::stream::{TcpStream, TcpState};
use crate::types::packet::TcpFlags;
use crate::types::PacketInfo;

/// 流管理器配置
#[derive(Debug, Clone)]
pub struct StreamManagerConfig {
    /// 流超时时间（秒）
    pub stream_timeout: Duration,
    /// 最大并发流数
    pub max_streams: usize,
    /// 清理间隔
    pub cleanup_interval: Duration,
    /// NPatch 阻断验证模式（None 表示关闭验证）
    pub verify_blocking: Option<crate::types::stream::BlockingMode>,
}

impl Default for StreamManagerConfig {
    fn default() -> Self {
        Self {
            stream_timeout: Duration::from_secs(300), // 5分钟
            max_streams: 100000,
            cleanup_interval: Duration::from_secs(60), // 1分钟
            verify_blocking: None,
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

            let stream = TcpStream::new(flow_key.clone());

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
            // 更新 ACK 号与累计接收字节
            if let Some(ack) = packet.tcp_ack {
                stream.update_sequence(ack, is_client, packet.payload_len as u32);
            }

            stream.connection.update_activity(packet.timestamp);

            let tcp_flags = TcpFlags::from_byte(packet.tcp_flags.unwrap_or(0));
            let syn_flag = tcp_flags.syn;
            let ack_flag = tcp_flags.ack;
            let fin_flag = tcp_flags.fin;
            let rst_flag = tcp_flags.rst;

            // NPatch 阻断验证
            if let Some(mode) = self.config.verify_blocking {
                // 关键顺序：verify_blocking 必须在 detect_*_first_data 之前调用，
                // 否则 hijack 注入报文（server->client 带负载）会先被
                // detect_server_first_data 当成「服务器首个真实数据」。
                stream.verify_blocking(&packet, mode);
                stream.detect_client_first_data(&packet);
                stream.detect_server_first_data(&packet);
            }

            // 如果是 RST 报文，使用专门的 RST 处理方法
            if rst_flag {
                if stream.handle_rst(&packet) {
                    // RST 报文有效：记录该报文后结束本次处理
                    // （状态已置为 Reset，连接已标记 close.reset）
                    stream.stats.update(packet.payload_len, direction, packet.timestamp);
                    return flow_key.clone();
                }
                // RST 报文无效：忽略其 RST 语义，但仍按普通报文计入统计
            }

            // 统计流的全部报文（含 RST 之后的报文）
            stream.stats.update(packet.payload_len, direction, packet.timestamp);

            // TCP 状态机转换（RST 已在上面单独处理）。
            // SynReceived 是必要的中间态：使 state==Established 等价于三次握手完成。
            // 元组顺序：(state, syn, ack, fin, is_client)
            let new_state = match (stream.state, syn_flag, ack_flag, fin_flag, is_client) {
                // CLOSED：等待握手开始
                (TcpState::Closed, true, false, _, true) => TcpState::SynSent,      // 客户端 SYN
                (TcpState::Closed, true, false, _, false) => TcpState::SynReceived, // 服务器 SYN（少见）
                (TcpState::Closed, true, true, _, _) => TcpState::SynReceived,      // 漏抓 SYN，先见 SYN-ACK

                // SYN_SENT：等待 SYN-ACK
                (TcpState::SynSent, true, true, _, _) => TcpState::SynReceived,     // 收到 SYN-ACK
                (TcpState::SynSent, false, true, _, _) => TcpState::Established,    // 直接 ACK（同时打开/丢包）

                // SYN_RECEIVED：等待三次握手的第三个 ACK
                (TcpState::SynReceived, false, true, _, _) => TcpState::Established,

                // ESTABLISHED：等待数据或 FIN
                (TcpState::Established, _, _, true, true) => TcpState::FinWait1,    // 客户端先发 FIN
                (TcpState::Established, _, _, true, false) => TcpState::CloseWait,  // 服务器先发 FIN

                // FIN_WAIT_1：客户端已发 FIN，等待服务器响应
                (TcpState::FinWait1, _, _, true, false) => TcpState::Closing,      // 同时收到对端 FIN
                (TcpState::FinWait1, _, true, false, false) => TcpState::FinWait2, // 收到对端 ACK

                // FIN_WAIT_2：等待对端 FIN
                (TcpState::FinWait2, _, _, true, false) => TcpState::TimeWait,

                // CLOSE_WAIT：等待本端（客户端）FIN
                (TcpState::CloseWait, _, _, true, true) => TcpState::LastAck,

                // CLOSING：等待 ACK
                (TcpState::Closing, _, true, _, _) => TcpState::TimeWait,

                // LAST_ACK：等待最后的 ACK
                (TcpState::LastAck, _, true, _, _) => TcpState::Closed,

                // 其他情况保持原状态
                (state, _, _, _, _) => state,
            };

            // 更新握手状态
            if syn_flag && !ack_flag {
                // 客户端 SYN —— 握手开始
                if is_client {
                    stream.connection.handshake.client_syn = true;
                    stream.connection.handshake.update(packet.timestamp);
                }
            } else if syn_flag && ack_flag {
                // SYN-ACK 包
                stream.connection.handshake.server_syn_ack = true;
                stream.connection.handshake.update(packet.timestamp);
            } else if ack_flag && !syn_flag && !fin_flag && !rst_flag {
                // 三次握手的第三个 ACK（必须来自客户端方向）
                if is_client
                    && stream.connection.handshake.client_syn
                    && stream.connection.handshake.server_syn_ack
                    && !stream.connection.handshake.client_ack
                {
                    stream.connection.handshake.client_ack = true;
                    // 握手完成，记录结束时间与握手耗时
                    stream.connection.handshake.update(packet.timestamp);
                }
            }

            // 记录四次挥手的 FIN
            if fin_flag {
                if is_client {
                    stream.connection.close.client_fin = true;
                } else {
                    stream.connection.close.server_fin = true;
                }
                stream.connection.close.update(packet.timestamp);
            }

            // 如果状态改变，更新状态
            if new_state != stream.state {
                stream.update_state(new_state, packet.timestamp);
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
            // 检查流是否超时（saturating_sub 防止 PCAP 时间戳晚于当前时间时下溢）
            if let Some(last_activity) = stream.connection.last_activity {
                if current_time.saturating_sub(last_activity) > timeout_micros {
                    to_remove.push(flow_key.clone());
                }
            } else {
                // 没有活动记录的流也移除
                to_remove.push(flow_key.clone());
            }
        }

        // 移除过期流
        for flow_key in to_remove {
            if self.streams.remove(&flow_key).is_some() {
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

    /// 消费管理器，取出其中所有流
    pub fn into_streams(self) -> Vec<TcpStream> {
        self.streams.into_values().collect()
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
            payload_len: 4,
            tcp_seq: Some(1000),
            tcp_ack: Some(2000),
            tcp_flags: Some(0x10), // ACK
            tcp_window: Some(8192),
            ip_ttl: None,
            ip_id: None,
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

    // ---- 以下为针对握手/重置判定的补充用例 ----

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
    const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

    /// 构造一个带指定方向、标志位与时间戳的 TCP PacketInfo。
    fn tcp(from_client: bool, flags: u8, ts: u64, payload_len: usize) -> PacketInfo {
        let (src_ip, dst_ip, src_port, dst_port) = if from_client {
            (CLIENT, SERVER, 50000u16, 80u16)
        } else {
            (SERVER, CLIENT, 80u16, 50000u16)
        };
        PacketInfo {
            timestamp: ts,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: 6,
            payload_len,
            tcp_seq: Some(1000),
            tcp_ack: Some(2000),
            tcp_flags: Some(flags),
            tcp_window: Some(64240),
            ip_ttl: None,
            ip_id: None,
        }
    }

    /// 通过 process_packet 走完整三次握手，应判定为「已建立」。
    #[test]
    fn test_process_packet_completes_handshake() {
        let mut manager = StreamManager::with_default_config();
        manager.process_packet(&tcp(true, 0x02, 100, 0)); // SYN
        manager.process_packet(&tcp(false, 0x12, 200, 0)); // SYN-ACK
        manager.process_packet(&tcp(true, 0x10, 300, 0)); // ACK

        let stream = manager.get_all_streams().next().unwrap();
        assert!(stream.connection.handshake.is_complete());
        assert_eq!(stream.state, TcpState::Established);
        assert!(stream.connection.established_time.is_some());
    }

    /// 仅 SYN+SYN-ACK 时握手未完成，状态停在 SYN_RECEIVED（不应提前到 ESTABLISHED）。
    #[test]
    fn test_process_packet_handshake_incomplete() {
        let mut manager = StreamManager::with_default_config();
        manager.process_packet(&tcp(true, 0x02, 100, 0)); // SYN
        manager.process_packet(&tcp(false, 0x12, 200, 0)); // SYN-ACK

        let stream = manager.get_all_streams().next().unwrap();
        assert!(!stream.connection.handshake.is_complete());
        assert_eq!(stream.state, TcpState::SynReceived);
    }

    /// RST 应被识别为异常重置。
    #[test]
    fn test_process_packet_detects_reset() {
        let mut manager = StreamManager::with_default_config();
        manager.process_packet(&tcp(true, 0x02, 100, 0)); // SYN
        manager.process_packet(&tcp(false, 0x12, 200, 0)); // SYN-ACK
        manager.process_packet(&tcp(true, 0x10, 300, 0)); // ACK
        manager.process_packet(&tcp(false, 0x04, 400, 0)); // RST

        let stream = manager.get_all_streams().next().unwrap();
        assert_eq!(stream.state, TcpState::Reset);
        assert!(stream.connection.close.reset);
        assert!(!stream.connection.close.is_graceful());
        assert_eq!(stream.stats.packet_count, 4);
    }

    /// 构造一个模拟 NPatch 朝客户端注入的 RST 报文（窗口888、TTL60、IP-ID 0x8866）。
    fn npatch_rst(ts: u64) -> PacketInfo {
        PacketInfo {
            timestamp: ts,
            src_ip: SERVER,
            dst_ip: CLIENT,
            src_port: 80,
            dst_port: 50000,
            protocol: 6,
            payload_len: 0,
            tcp_seq: Some(1000),
            tcp_ack: Some(2000),
            tcp_flags: Some(0x04), // RST
            tcp_window: Some(888),
            ip_ttl: Some(60),
            ip_id: Some(0x8866),
        }
    }

    /// process_packet 驱动的 SYN 阻断验证：握手完成前收到 NPatch RST。
    #[test]
    fn test_process_packet_verify_syn_blocking() {
        let config = StreamManagerConfig {
            verify_blocking: Some(crate::types::stream::BlockingMode::Syn),
            ..StreamManagerConfig::default()
        };
        let mut manager = StreamManager::new(config);
        manager.process_packet(&tcp(true, 0x02, 100, 0)); // SYN
        manager.process_packet(&tcp(false, 0x12, 200, 0)); // SYN-ACK
        manager.process_packet(&npatch_rst(300)); // NPatch 注入 RST

        let stream = manager.get_all_streams().next().unwrap();
        assert!(stream.verification.blocked, "应检测到 SYN 阻断成功");
        assert!(!stream.connection.handshake.is_complete());
        assert_eq!(stream.verification.matched_window, Some(888));
    }
}