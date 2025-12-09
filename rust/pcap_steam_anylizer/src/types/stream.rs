//! 流信息类型定义
//!
//! 定义了用于表示TCP流的各种数据结构，包括TCP状态、连接信息等

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use super::flow::{FlowKey, FlowStats};
use super::PacketInfo;
use crate::types::packet::TcpFlags;

/// TCP连接状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    /// 未建立连接
    Closed,
    /// SYN已发送
    SynSent,
    /// SYN已接收
    SynReceived,
    /// 连接已建立
    Established,
    /// FIN等待1
    FinWait1,
    /// FIN等待2
    FinWait2,
    /// 关闭等待
    CloseWait,
    /// 正在关闭
    Closing,
    /// 最后的ACK等待
    LastAck,
    /// 时间等待
    TimeWait,
    /// 连接被重置
    Reset,
}

impl TcpState {
    /// 获取状态的字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECEIVED",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Reset => "RESET",
        }
    }

    /// 检查是否是活动连接状态
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::SynSent | Self::SynReceived | Self::Established
        )
    }

    /// 检查是否是关闭中状态
    pub fn is_closing(&self) -> bool {
        matches!(
            self,
            Self::FinWait1 | Self::FinWait2 | Self::CloseWait | Self::Closing | Self::LastAck
        )
    }

    /// 检查是否是已关闭状态
    pub fn is_closed(&self) -> bool {
        matches!(self, Self::Closed | Self::TimeWait | Self::Reset)
    }
}

/// TCP握手状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpHandshake {
    /// 是否收到客户端SYN
    pub client_syn: bool,
    /// 是否收到服务器SYN-ACK
    pub server_syn_ack: bool,
    /// 是否收到客户端ACK
    pub client_ack: bool,
    /// 握手开始时间
    pub start_time: Option<u64>,
    /// 握手结束时间
    pub end_time: Option<u64>,
    /// 握手持续时间（微秒）
    pub duration: Option<u64>,
}

impl TcpHandshake {
    /// 创建新的握手状态
    pub fn new() -> Self {
        Self {
            client_syn: false,
            server_syn_ack: false,
            client_ack: false,
            start_time: None,
            end_time: None,
            duration: None,
        }
    }

    /// 检查握手是否完成
    pub fn is_complete(&self) -> bool {
        self.client_syn && self.server_syn_ack && self.client_ack
    }

    /// 更新握手状态
    pub fn update(&mut self, timestamp: u64) {
        if self.start_time.is_none() {
            self.start_time = Some(timestamp);
        }

        if self.is_complete() && self.end_time.is_none() {
            self.end_time = Some(timestamp);
            if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
                self.duration = Some(end - start);
            }
        }
    }

    /// 获取握手持续时间（毫秒）
    pub fn duration_ms(&self) -> Option<f64> {
        self.duration.map(|micros| micros as f64 / 1000.0)
    }
}

impl Default for TcpHandshake {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP关闭状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpClose {
    /// 客户端是否发送FIN
    pub client_fin: bool,
    /// 服务器是否发送FIN
    pub server_fin: bool,
    /// 是否收到客户端ACK
    pub client_ack: bool,
    /// 是否收到服务器ACK
    pub server_ack: bool,
    /// 是否被RST重置
    pub reset: bool,
    /// 关闭开始时间
    pub start_time: Option<u64>,
    /// 关闭结束时间
    pub end_time: Option<u64>,
    /// 关闭持续时间（微秒）
    pub duration: Option<u64>,
}

impl TcpClose {
    /// 创建新的关闭状态
    pub fn new() -> Self {
        Self {
            client_fin: false,
            server_fin: false,
            client_ack: false,
            server_ack: false,
            reset: false,
            start_time: None,
            end_time: None,
            duration: None,
        }
    }

    /// 检查是否是正常关闭
    pub fn is_graceful(&self) -> bool {
        self.client_fin && self.server_fin && !self.reset
    }

    /// 检查是否已完全关闭
    pub fn is_complete(&self) -> bool {
        (self.client_fin && self.server_fin) || self.reset
    }

    /// 更新关闭状态
    pub fn update(&mut self, timestamp: u64) {
        if self.start_time.is_none() && (self.client_fin || self.server_fin || self.reset) {
            self.start_time = Some(timestamp);
        }

        if self.is_complete() && self.end_time.is_none() {
            self.end_time = Some(timestamp);
            if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
                self.duration = Some(end - start);
            }
        }
    }

    /// 获取关闭持续时间（毫秒）
    pub fn duration_ms(&self) -> Option<f64> {
        self.duration.map(|micros| micros as f64 / 1000.0)
    }
}

impl Default for TcpClose {
    fn default() -> Self {
        Self::new()
    }
}

/// 连接信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// 握手状态
    pub handshake: TcpHandshake,
    /// 关闭状态
    pub close: TcpClose,
    /// 连接建立时间
    pub established_time: Option<u64>,
    /// 最后活动时间
    pub last_activity: Option<u64>,
    /// 连接持续时间（微秒）
    pub duration: Option<u64>,
    /// 客户端TCP窗口大小（初始值）
    pub client_window: Option<u16>,
    /// 服务器TCP窗口大小（初始值）
    pub server_window: Option<u16>,
    /// 客户端MSS
    pub client_mss: Option<u16>,
    /// 服务器MSS
    pub server_mss: Option<u16>,
    /// 是否启用了SACK
    pub sack_enabled: bool,
    /// 是否启用了时间戳
    pub timestamps_enabled: bool,
    /// 是否启用了WS（窗口缩放）
    pub window_scaling: bool,
    /// 重传次数
    pub retransmission_count: u32,
    /// 乱序包数量
    pub out_of_order_count: u32,
    /// 重复ACK数量
    pub duplicate_ack_count: u32,
}

impl ConnectionInfo {
    /// 创建新的连接信息
    pub fn new() -> Self {
        Self {
            handshake: TcpHandshake::new(),
            close: TcpClose::new(),
            established_time: None,
            last_activity: None,
            duration: None,
            client_window: None,
            server_window: None,
            client_mss: None,
            server_mss: None,
            sack_enabled: false,
            timestamps_enabled: false,
            window_scaling: false,
            retransmission_count: 0,
            out_of_order_count: 0,
            duplicate_ack_count: 0,
        }
    }

    /// 更新最后活动时间
    pub fn update_activity(&mut self, timestamp: u64) {
        self.last_activity = Some(timestamp);

        // 如果连接已建立，计算持续时间
        if let (Some(established), Some(last)) = (self.established_time, self.last_activity) {
            self.duration = Some(last - established);
        }
    }

    /// 标记连接已建立
    pub fn set_established(&mut self, timestamp: u64) {
        self.established_time = Some(timestamp);
        self.last_activity = Some(timestamp);
    }

    /// 获取连接持续时间（秒）
    pub fn duration_seconds(&self) -> Option<f64> {
        self.duration.map(|micros| micros as f64 / 1_000_000.0)
    }

    /// 检查是否是活跃连接
    pub fn is_active(&self) -> bool {
        self.handshake.is_complete() && !self.close.is_complete()
    }

    /// 获取连接质量分数（0-100）
    pub fn quality_score(&self) -> f64 {
        let mut score = 100.0;

        // 根据重传次数扣分
        score -= (self.retransmission_count as f64) * 2.0;

        // 根据乱序包数量扣分
        score -= (self.out_of_order_count as f64) * 1.0;

        // 根据重复ACK数量扣分
        score -= (self.duplicate_ack_count as f64) * 0.5;

        // 如果被重置，严重扣分
        if self.close.reset {
            score -= 50.0;
        }

        score.max(0.0).min(100.0)
    }
}

impl Default for ConnectionInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP流
///
/// 包含一个TCP流的所有信息和统计数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStream {
    /// 流键值
    pub flow_key: FlowKey,
    /// 当前TCP状态
    pub state: TcpState,
    /// 连接信息
    pub connection: ConnectionInfo,
    /// 流统计信息
    pub stats: FlowStats,
    /// 客户端序列号
    pub client_seq: Option<u32>,
    /// 服务器序列号
    pub client_ack: Option<u32>,
    /// 服务器序列号
    pub server_seq: Option<u32>,
    /// 服务器ACK号
    pub server_ack: Option<u32>,
    /// 客户端最后接收的数据量
    pub client_received: u64,
    /// 服务器最后接收的数据量
    pub server_received: u64,
    /// 数据重组缓冲区
    pub reassembly_buffer: BTreeMap<u32, Vec<u8>>,
    /// 流的标签
    pub labels: Vec<String>,
    /// 流的元数据
    pub metadata: BTreeMap<String, String>,
    /// RST 报文终止时间（微秒）
    pub rst_time: Option<u64>,
    /// 是否收到SYN包后窗口大小为888的RST-ACK报文
    pub has_rst_888_after_syn: bool,
    /// 是否在SYN包后直接收到窗口大小为888的RST-ACK报文（中间没有其他报文）
    pub has_immediate_rst_888_after_syn: bool,
    /// SYN包后的数据包计数（用于检测是否紧跟RST-888）
    pub packets_since_syn: u32,
    /// 是否在三次握手完成后的ACK报文后收到窗口大小为888的RST-ACK报文
    pub has_rst_888_after_handshake_ack: bool,
    /// 三次握手完成后的ACK报文后的数据包计数
    pub packets_since_handshake_ack: u32,
}

impl TcpStream {
    /// 创建新的TCP流
    pub fn new(flow_key: FlowKey) -> Self {
        Self {
            flow_key,
            state: TcpState::Closed,
            connection: ConnectionInfo::new(),
            stats: FlowStats::new(),
            client_seq: None,
            client_ack: None,
            server_seq: None,
            server_ack: None,
            client_received: 0,
            server_received: 0,
            reassembly_buffer: BTreeMap::new(),
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            rst_time: None,
            has_rst_888_after_syn: false,
            has_immediate_rst_888_after_syn: false,
            packets_since_syn: 0,
            has_rst_888_after_handshake_ack: false,
            packets_since_handshake_ack: 0,
        }
    }

    /// 更新TCP状态
    pub fn update_state(&mut self, new_state: TcpState, timestamp: u64) {
        // 从CLOSED到ESTABLISHED的转换记录连接建立时间
        if self.state == TcpState::Closed && new_state == TcpState::Established {
            self.connection.set_established(timestamp);
        }

        // 如果转换到 Reset 状态，记录 RST 时间
        if new_state == TcpState::Reset && self.rst_time.is_none() {
            self.rst_time = Some(timestamp);
        }

        self.state = new_state;
        self.connection.update_activity(timestamp);
    }

    /// 处理 RST 报文，验证有效性并更新状态
    pub fn handle_rst(&mut self, packet: &PacketInfo) -> bool {
        // 验证 RST 报文的有效性
        if !self.is_valid_rst(packet) {
            return false;
        }

        // 记录 RST 时间
        if self.rst_time.is_none() {
            self.rst_time = Some(packet.timestamp);
        }

        // 更新状态为 Reset
        self.update_state(TcpState::Reset, packet.timestamp);
        true
    }

    /// 验证 RST 报文的有效性
    fn is_valid_rst(&self, packet: &PacketInfo) -> bool {
        // 检查是否有序列号
        let seq = match packet.tcp_seq {
            Some(seq) => seq,
            None => return false,
        };

        // 检查流是否已建立
        if !matches!(self.state,
            TcpState::Established |
            TcpState::SynReceived |
            TcpState::SynSent |
            TcpState::FinWait1 |
            TcpState::FinWait2 |
            TcpState::CloseWait |
            TcpState::Closing |
            TcpState::LastAck |
            TcpState::TimeWait
        ) {
            // 流还未建立或已关闭，RST 无效
            return false;
        }

        // 检查序列号是否在合理范围内
        if let (Some(client_seq), Some(server_seq)) = (self.client_seq, self.server_seq) {
            // 对于客户端发送的 RST，序列号应该接近客户端的序列号
            // 对于服务器发送的 RST，序列号应该接近服务器的序列号
            let is_from_client = packet.src_ip == *self.flow_key.src_ip() &&
                               packet.src_port == self.flow_key.src_port();

            let expected_seq = if is_from_client { client_seq } else { server_seq };

            // 允许一定的序列号差异（考虑窗口大小）
            let seq_diff = if seq >= expected_seq {
                seq - expected_seq
            } else {
                expected_seq - seq
            };

            // 如果序列号差异过大，认为 RST 无效
            if seq_diff > 65535 {
                return false;
            }
        }

        true
    }

    /// 更新序列号信息
    pub fn update_sequence(&mut self, seq: u32, ack: u32, is_client: bool, bytes: u32) {
        if is_client {
            if self.client_seq.is_none() {
                self.client_seq = Some(seq);
            }
            self.client_ack = Some(ack);
            if bytes > 0 {
                self.server_received += bytes as u64;
            }
        } else {
            if self.server_seq.is_none() {
                self.server_seq = Some(seq);
            }
            self.server_ack = Some(ack);
            if bytes > 0 {
                self.client_received += bytes as u64;
            }
        }
    }

    /// 添加数据到重组缓冲区
    pub fn add_to_reassembly(&mut self, seq: u32, data: Vec<u8>) {
        self.reassembly_buffer.insert(seq, data);
    }

    /// 检测并处理SYN包后的窗口大小为888的RST-ACK报文
    /// 注意：此函数只检测RST-ACK包（RST且ACK），不检测纯RST包
    pub fn detect_rst_888_after_syn(&mut self, packet: &PacketInfo) {
        // 检查是否是TCP包
        if packet.protocol != 6 {
            return;
        }

        // 获取TCP标志
        let tcp_flags = match packet.tcp_flags {
            Some(flags) => TcpFlags::from_byte(flags),
            None => return,
        };

        // 只处理RST-ACK包（RST且ACK）
        if tcp_flags.is_rst() && tcp_flags.is_ack_only() {
            // 检查窗口大小是否为888
            if packet.tcp_window == Some(888) {
                // 检查是否已经收到了SYN包
                if self.connection.handshake.client_syn {
                    self.has_rst_888_after_syn = true;

                    // 检查是否紧跟在SYN包后
                    // packets_since_syn在syn_packet_received中已被重置为0
                    // 在update_packet_stats中会被递增
                    // 所以这里检查递增前的值
                    if self.packets_since_syn == 0 {
                        self.has_immediate_rst_888_after_syn = true;
                    }
                }
            }
        }
    }

    /// 检测三次握手ACK后的RST报文（非RST-ACK）
    pub fn detect_rst_after_handshake_ack(&mut self, packet: &PacketInfo) {
        // 检查是否是TCP包
        if packet.protocol != 6 {
            return;
        }

        // 获取TCP标志
        let tcp_flags = match packet.tcp_flags {
            Some(flags) => TcpFlags::from_byte(flags),
            None => return,
        };

        // 只处理RST包（非RST-ACK）
        if tcp_flags.is_rst() && !tcp_flags.is_ack_only() {
            // 检查窗口大小是否为888
            if packet.tcp_window == Some(888) {
                // 检查三次握手是否已完成
                if self.connection.handshake.is_complete() {
                    // 检查是否在三次握手ACK后立即收到RST-888
                    // 三次握手的ACK后，packets_since_handshake_ack会被设置为1
                    // 紧接着的RST包，此时packets_since_handshake_ack应该是1（还未递增）
                    if self.packets_since_handshake_ack == 1 {
                        self.has_rst_888_after_handshake_ack = true;
                    }
                }
            }
        }
    }

    /// 尝试重组数据
    pub fn try_reassemble(&mut self) -> Option<Vec<u8>> {
        if self.reassembly_buffer.is_empty() {
            return None;
        }

        // 获取期望的下一个序列号
        let next_seq = self.client_received as u32;

        let mut assembled = Vec::new();
        let mut current_seq = next_seq;

        // 尝试按序组装数据
        while let Some(data) = self.reassembly_buffer.get(&current_seq) {
            let data_len = data.len() as u32;
            assembled.extend_from_slice(data);
            current_seq += data_len;
            self.reassembly_buffer.remove(&(current_seq - data_len));
        }

        if assembled.is_empty() {
            None
        } else {
            Some(assembled)
        }
    }

    /// 获取客户端IP
    pub fn client_ip(&self) -> &IpAddr {
        self.flow_key.src_ip()
    }

    /// 获取服务器IP
    pub fn server_ip(&self) -> &IpAddr {
        self.flow_key.dst_ip()
    }

    /// 获取客户端端口
    pub fn client_port(&self) -> u16 {
        self.flow_key.src_port()
    }

    /// 获取服务器端口
    pub fn server_port(&self) -> u16 {
        self.flow_key.dst_port()
    }

    /// 检查是否是HTTP流
    pub fn is_http(&self) -> bool {
        self.server_port() == 80 || self.server_port() == 8080 || self.client_port() == 80 || self.client_port() == 8080
    }

    /// 检查是否是HTTPS流
    pub fn is_https(&self) -> bool {
        self.server_port() == 443 || self.client_port() == 443
    }

    /// 检查是否是SSH流
    pub fn is_ssh(&self) -> bool {
        self.server_port() == 22 || self.client_port() == 22
    }

    /// 添加标签
    pub fn add_label(&mut self, label: String) {
        if !self.labels.contains(&label) {
            self.labels.push(label);
        }
    }

    /// 设置元数据
    pub fn set_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// 获取元数据
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// 添加事件记录
    pub fn add_event(&mut self, event: StreamEventRecord) {
        // 将事件记录存储在metadata中，简化实现
        // 实际应用中可能需要专门的events字段
        let event_key = format!("event_{}", event.timestamp);
        let event_data = format!("{}: {}", event.event.as_str(), event.description);
        self.set_metadata(event_key, event_data);
    }

    /// 获取流的持续时间
    pub fn duration(&self) -> Option<Duration> {
        match (self.connection.established_time, self.connection.last_activity) {
            (Some(start), Some(end)) => Some(Duration::from_micros(end - start)),
            _ => None,
        }
    }

    /// 获取客户端吞吐量（字节/秒）
    pub fn client_throughput(&self) -> f64 {
        match self.duration() {
            Some(duration) if duration.as_secs_f64() > 0.0 => {
                self.client_received as f64 / duration.as_secs_f64()
            }
            _ => 0.0,
        }
    }

    /// 获取服务器吞吐量（字节/秒）
    pub fn server_throughput(&self) -> f64 {
        match self.duration() {
            Some(duration) if duration.as_secs_f64() > 0.0 => {
                self.server_received as f64 / duration.as_secs_f64()
            }
            _ => 0.0,
        }
    }

    /// 获取流的摘要信息
    pub fn summary(&self) -> String {
        format!(
            "TCP Stream: {} -> {} | State: {} | Packets: {} | Duration: {:.3}s | Client: {} bytes | Server: {} bytes",
            self.client_ip(),
            self.server_ip(),
            self.state.as_str(),
            self.stats.packet_count,
            self.duration().map(|d| d.as_secs_f64()).unwrap_or(0.0),
            self.client_received,
            self.server_received
        )
    }
}

/// 流事件类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamEvent {
    /// 流创建
    StreamCreated,
    /// 数据包接收
    PacketReceived,
    /// 乱序数据包
    OutOfOrderPacket,
    /// 数据包重传
    Retransmission,
    /// 重复ACK
    DuplicateAck,
    /// 窗口更新
    WindowUpdate,
    /// 流关闭
    StreamClosed,
    /// 流重置
    StreamReset,
    /// 超时
    Timeout,
    /// 错误
    Error(String),
}

impl StreamEvent {
    /// 获取事件的字符串表示
    pub fn as_str(&self) -> &str {
        match self {
            Self::StreamCreated => "Stream Created",
            Self::PacketReceived => "Packet Received",
            Self::OutOfOrderPacket => "Out of Order Packet",
            Self::Retransmission => "Retransmission",
            Self::DuplicateAck => "Duplicate ACK",
            Self::WindowUpdate => "Window Update",
            Self::StreamClosed => "Stream Closed",
            Self::StreamReset => "Stream Reset",
            Self::Timeout => "Timeout",
            Self::Error(msg) => &msg,
        }
    }
}

/// 流事件记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEventRecord {
    /// 事件时间戳
    pub timestamp: u64,
    /// 事件类型
    pub event: StreamEvent,
    /// 事件描述
    pub description: String,
    /// 相关数据包序列号（可选）
    pub sequence: Option<u32>,
    /// 相关数据（可选）
    pub data: Option<Vec<u8>>,
}

impl StreamEventRecord {
    /// 创建新的事件记录
    pub fn new(timestamp: u64, event: StreamEvent, description: String) -> Self {
        Self {
            timestamp,
            event,
            description,
            sequence: None,
            data: None,
        }
    }

    /// 设置序列号
    pub fn with_sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// 设置数据
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }
}