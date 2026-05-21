//! 流信息类型定义
//!
//! 定义了用于表示TCP流的各种数据结构，包括TCP状态、连接信息等

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

/// NPatch 注入报文的通用窗口签名（主机字节序）
///
/// NPatch 阻断设备注入的 RST / hijack 报文统一把 TCP 窗口大小设为 888
/// （`NPATCH_RST_WINDOW_SIZE_HOST`），NPatch 自身亦用 `RST && window==888`
/// 来识别自己产生的报文。
pub const NPATCH_RST_WINDOW_SIZE_HOST: u16 = 888;

/// NPatch hijack 报文的 IPv4 TTL 签名
pub const NPATCH_HIJACK_TTL: u8 = 60;

/// NPatch hijack 报文的 IPv4 identification 签名（源码字面值）
pub const NPATCH_HIJACK_IP_ID: u16 = 0x6688;

/// NPatch hijack 报文 identification 在网络上呈现的字节交换值
///
/// NPatch 源码写的是 `0x6688`，但赋值时未做主机/网络字节序转换，
/// 实际抓包中该字段呈现为字节交换后的 `0x8866`（已被真实样本证实）。
pub const NPATCH_HIJACK_IP_ID_SWAPPED: u16 = 0x8866;

/// 判断 IPv4 identification 是否符合 NPatch hijack 签名（接受两种字节序）
pub fn is_npatch_hijack_ip_id(ip_id: Option<u16>) -> bool {
    matches!(
        ip_id,
        Some(NPATCH_HIJACK_IP_ID) | Some(NPATCH_HIJACK_IP_ID_SWAPPED)
    )
}

/// 判断窗口大小是否符合 NPatch 注入签名（888 或 888 的整数倍）
///
/// 沿用既有 RST-888 检测的「888 整数倍」约定，对偶尔出现的窗口缩放等情况更宽容。
pub fn is_npatch_window(window: Option<u16>) -> bool {
    matches!(window, Some(w) if w == NPATCH_RST_WINDOW_SIZE_HOST
        || (w > NPATCH_RST_WINDOW_SIZE_HOST && w % NPATCH_RST_WINDOW_SIZE_HOST == 0))
}

/// NPatch 阻断方式
///
/// 对应 NPatch 设备的阻断/防护策略，用于选择验证逻辑。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockingMode {
    /// ACK 阻断：三次握手完成后注入 RST(win888)
    Ack,
    /// SYN 阻断：握手完成前注入 RST(win888)
    Syn,
    /// Hijack 劫持：注入带伪造负载的 PSH/ACK(win888) 冒充服务器响应
    Hijack,
    /// Web 扫描防护：对 web 端口流在客户端请求后注入 RST 或 hijack 报文
    WebScan,
    /// 单向阻断（通用）：服务器返回有效数据前，NPatch 已注入 RST 或 hijack 报文
    OneWay,
}

impl BlockingMode {
    /// 模式的中文名称
    pub fn name_cn(&self) -> &'static str {
        match self {
            Self::Ack => "ACK 阻断",
            Self::Syn => "SYN 阻断",
            Self::Hijack => "Hijack 劫持",
            Self::WebScan => "Web 扫描防护",
            Self::OneWay => "单向阻断",
        }
    }

    /// 模式的简短英文标识（用于导出文件名等）
    pub fn slug(&self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Syn => "syn",
            Self::Hijack => "hijack",
            Self::WebScan => "web_scan",
            Self::OneWay => "one_way",
        }
    }

    /// 模式判定标准的说明文字
    pub fn description(&self) -> &'static str {
        match self {
            Self::Ack => "三次握手完成后，服务器返回有效数据前，向客户端注入 RST(窗口888)",
            Self::Syn => "三次握手完成前，向客户端注入 RST(窗口888)",
            Self::Hijack => "握手完成、客户端发出请求后，向客户端注入带伪造负载的 PSH/ACK(窗口888)",
            Self::WebScan => "web 端口流在客户端发出请求后，向客户端注入 RST 或 PSH/ACK(窗口888)",
            Self::OneWay => "服务器返回有效数据前，NPatch 已向客户端注入 RST 或 hijack 报文(窗口888)",
        }
    }
}

/// Hijack 报文可信度
///
/// 依据注入报文是否带 NPatch 的 IPv4 TTL / identification 签名来评估。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HijackConfidence {
    /// TTL 与 IP-id 签名都命中
    High,
    /// TTL 或 IP-id 签名命中其一
    Medium,
    /// 仅窗口 888 命中
    Low,
}

impl HijackConfidence {
    /// 可信度的中文名称
    pub fn name_cn(&self) -> &'static str {
        match self {
            Self::High => "高",
            Self::Medium => "中",
            Self::Low => "低",
        }
    }

    /// 依据 TTL / IP-id 签名命中情况评估可信度
    fn from_signatures(ttl_ok: bool, id_ok: bool) -> Self {
        match (ttl_ok, id_ok) {
            (true, true) => Self::High,
            (true, false) | (false, true) => Self::Medium,
            (false, false) => Self::Low,
        }
    }
}

/// NPatch 阻断验证结果
///
/// 记录某条 TCP 流在指定阻断模式下「是否被成功阻断」，以及命中的阻断报文特征。
/// 仅在阻断验证模式下被填充。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockingVerification {
    /// 是否判定为已被成功阻断
    pub blocked: bool,
    /// 判定原因（人类可读）
    pub reason: String,
    /// hijack 模式下的可信度，其它模式为 None
    pub confidence: Option<HijackConfidence>,
    /// 命中阻断报文的 TCP 标志位
    pub matched_flags: Option<u8>,
    /// 命中阻断报文的 TCP 窗口大小
    pub matched_window: Option<u16>,
    /// 命中阻断报文的 IPv4 TTL
    pub matched_ttl: Option<u8>,
    /// 命中阻断报文的 IPv4 identification
    pub matched_ip_id: Option<u16>,
    /// 命中阻断报文是否朝向客户端
    pub matched_to_client: Option<bool>,
    /// 命中阻断报文的时间戳（微秒）
    pub matched_timestamp: Option<u64>,
    /// 命中阻断报文的负载长度
    pub matched_payload_len: Option<usize>,
}

impl BlockingVerification {
    /// 创建初始（未阻断）状态
    pub fn new() -> Self {
        Self {
            blocked: false,
            reason: "未检测到阻断报文".to_string(),
            confidence: None,
            matched_flags: None,
            matched_window: None,
            matched_ttl: None,
            matched_ip_id: None,
            matched_to_client: None,
            matched_timestamp: None,
            matched_payload_len: None,
        }
    }

    /// 记录一次成功的阻断匹配
    fn mark_blocked(&mut self, pkt: &PacketInfo, to_client: bool, reason: String) {
        self.blocked = true;
        self.reason = reason;
        self.matched_flags = pkt.tcp_flags;
        self.matched_window = pkt.tcp_window;
        self.matched_ttl = pkt.ip_ttl;
        self.matched_ip_id = pkt.ip_id;
        self.matched_to_client = Some(to_client);
        self.matched_timestamp = Some(pkt.timestamp);
        self.matched_payload_len = Some(pkt.payload_len);
    }
}

impl Default for BlockingVerification {
    fn default() -> Self {
        Self::new()
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
                // 使用 saturating_sub 防止报文乱序时下溢 panic
                self.duration = Some(end.saturating_sub(start));
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
                // 使用 saturating_sub 防止报文乱序时下溢 panic
                self.duration = Some(end.saturating_sub(start));
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
        // 使用 saturating_sub 防止报文乱序时下溢 panic
        if let (Some(established), Some(last)) = (self.established_time, self.last_activity) {
            self.duration = Some(last.saturating_sub(established));
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
    /// 客户端最近发送的 ACK 号（用于重传检测）
    pub client_ack: Option<u32>,
    /// 服务器最近发送的 ACK 号（用于重传检测）
    pub server_ack: Option<u32>,
    /// 客户端累计接收的数据字节数
    pub client_received: u64,
    /// 服务器累计接收的数据字节数
    pub server_received: u64,
    /// RST 报文终止时间（微秒）
    pub rst_time: Option<u64>,
    /// 服务器首次发送「有效数据」的时间（已排除 NPatch 注入报文）
    pub server_first_data_time: Option<u64>,
    /// 客户端首次发送带载荷数据包的时间
    pub client_first_data_time: Option<u64>,
    /// NPatch 阻断验证状态（仅在阻断验证模式下填充）
    pub verification: BlockingVerification,
}

impl TcpStream {
    /// 创建新的TCP流
    pub fn new(flow_key: FlowKey) -> Self {
        Self {
            flow_key,
            state: TcpState::Closed,
            connection: ConnectionInfo::new(),
            stats: FlowStats::new(),
            client_ack: None,
            server_ack: None,
            client_received: 0,
            server_received: 0,
            rst_time: None,
            server_first_data_time: None,
            client_first_data_time: None,
            verification: BlockingVerification::new(),
        }
    }

    /// 更新TCP状态
    pub fn update_state(&mut self, new_state: TcpState, timestamp: u64) {
        // 任何状态首次进入 ESTABLISHED 时，记录连接建立时间
        if self.state != TcpState::Established && new_state == TcpState::Established {
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

        // 记录连接被 RST 重置
        self.connection.close.reset = true;
        self.connection.close.update(packet.timestamp);

        // 更新状态为 Reset
        self.update_state(TcpState::Reset, packet.timestamp);
        true
    }

    /// 验证 RST 报文的有效性
    ///
    /// 仅依据连接状态判定：连接必须处于「已发起但尚未关闭」的状态，
    /// 才认为 RST 能终止它（可过滤掉对已关闭连接重复出现的 RST）。
    fn is_valid_rst(&self, packet: &PacketInfo) -> bool {
        // RST 报文必须带序列号
        if packet.tcp_seq.is_none() {
            return false;
        }

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

        true
    }

    /// 更新 ACK 号与累计接收字节数
    pub fn update_sequence(&mut self, ack: u32, is_client: bool, bytes: u32) {
        if is_client {
            self.client_ack = Some(ack);
            self.server_received += bytes as u64;
        } else {
            self.server_ack = Some(ack);
            self.client_received += bytes as u64;
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

    /// 是否是 web 端口流（HTTP/HTTPS/常见 web 端口）
    pub fn is_web_flow(&self) -> bool {
        self.is_http() || self.is_https() || matches!(self.server_port(), 8000 | 8080)
    }

    /// 获取流的持续时间
    pub fn duration(&self) -> Option<Duration> {
        match (self.connection.established_time, self.connection.last_activity) {
            // 使用 saturating_sub 防止报文乱序时下溢 panic
            (Some(start), Some(end)) => Some(Duration::from_micros(end.saturating_sub(start))),
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

    /// 检测服务器首次发送「有效数据」的数据包
    ///
    /// 协议栈层面的关键点：NPatch 注入的 hijack 报文也是 服务器->客户端 方向
    /// 且带负载，但它**不是**服务器的真实响应。因此此处排除带 NPatch 签名
    /// （窗口 888）的报文，以及 RST 等控制报文，只记录服务器真实应用层数据。
    pub fn detect_server_first_data(&mut self, packet: &PacketInfo) {
        // 检查是否是TCP包
        if packet.protocol != 6 {
            return;
        }

        // 检查是否是服务器发送给客户端
        let is_server_to_client = packet.src_ip == *self.flow_key.dst_ip()
            && packet.src_port == self.flow_key.dst_port();
        if !is_server_to_client {
            return;
        }

        // 如果已经记录过，不再处理
        if self.server_first_data_time.is_some() {
            return;
        }

        // 排除 NPatch 注入报文：窗口 888 的报文不算服务器真实数据
        if is_npatch_window(packet.tcp_window) {
            return;
        }

        // 排除 RST 等控制报文（RST 不携带有效应用数据）
        if let Some(flags) = packet.tcp_flags {
            if TcpFlags::from_byte(flags).is_rst() {
                return;
            }
        }

        // 记录服务器首次发送有效数据的时间
        if packet.payload_len > 0 {
            self.server_first_data_time = Some(packet.timestamp);
        }
    }

    /// 检测客户端首次发送带载荷的数据包
    pub fn detect_client_first_data(&mut self, packet: &PacketInfo) {
        // 检查是否是TCP包
        if packet.protocol != 6 {
            return;
        }

        // 检查是否是客户端发送给服务器
        let is_client_to_server = packet.src_ip == *self.flow_key.src_ip() &&
                                   packet.src_port == self.flow_key.src_port();

        if !is_client_to_server {
            return;
        }

        // 如果已经记录过，不再处理
        if self.client_first_data_time.is_some() {
            return;
        }

        // 记录客户端首次发送有效数据的时间
        if packet.payload_len > 0 {
            self.client_first_data_time = Some(packet.timestamp);
        }
    }

    /// NPatch 阻断验证：判定本条流在指定模式下是否被成功阻断
    ///
    /// 重要：必须在 `detect_client_first_data` / `detect_server_first_data`
    /// **之前**对当前报文调用，否则 hijack 的注入报文（server->client 带负载）
    /// 会先被 `detect_server_first_data` 当成「服务器首个真实数据」，
    /// 导致 hijack 判不出来。
    pub fn verify_blocking(&mut self, packet: &PacketInfo, mode: BlockingMode) {
        if packet.protocol != 6 {
            return;
        }
        // 已判定则幂等返回，保留首个命中报文
        if self.verification.blocked {
            return;
        }

        let flags = match packet.tcp_flags {
            Some(f) => TcpFlags::from_byte(f),
            None => return,
        };

        // NPatch 只朝扫描器/客户端方向注入阻断报文，其它方向无需判定
        let to_client = packet.dst_ip == *self.flow_key.src_ip()
            && packet.dst_port == self.flow_key.src_port();
        if !to_client {
            return;
        }

        let win888 = is_npatch_window(packet.tcp_window);
        let is_rst = flags.is_rst();
        // hijack 注入报文形态：带负载的 PSH/ACK
        let is_hijack = flags.is_psh_ack() && packet.payload_len > 0;
        let handshake_done = self.connection.handshake.is_complete();
        let server_replied = self.server_first_data_time.is_some();
        let client_requested = self.client_first_data_time.is_some();

        let hit = match mode {
            BlockingMode::Syn => {
                (is_rst && win888 && !handshake_done).then(|| {
                    "SYN 阻断成功：三次握手完成前收到 RST(窗口888)".to_string()
                })
            }
            BlockingMode::Ack => {
                (is_rst && win888 && handshake_done && !server_replied).then(|| {
                    "ACK 阻断成功：三次握手完成后、服务器返回有效数据前收到 RST(窗口888)"
                        .to_string()
                })
            }
            BlockingMode::Hijack => {
                if is_hijack && win888 && handshake_done && client_requested && !server_replied {
                    let confidence = HijackConfidence::from_signatures(
                        packet.ip_ttl == Some(NPATCH_HIJACK_TTL),
                        is_npatch_hijack_ip_id(packet.ip_id),
                    );
                    self.verification.confidence = Some(confidence);
                    Some(format!(
                        "Hijack 成功：向客户端注入 PSH/ACK(窗口888) 伪造响应（可信度{}）",
                        confidence.name_cn()
                    ))
                } else {
                    None
                }
            }
            BlockingMode::WebScan => {
                (self.is_web_flow() && win888 && client_requested && !server_replied
                    && (is_rst || is_hijack))
                .then(|| {
                    let kind = if is_rst { "RST(窗口888)" } else { "PSH/ACK(窗口888)" };
                    format!("Web 扫描防护成功：客户端请求后向客户端注入 {}", kind)
                })
            }
            // 协议栈层面的通用判定：服务器返回有效数据前（server_first_data_time
            // 已排除 NPatch 注入报文），收到窗口888 的 RST 或 hijack 即算阻断成功
            BlockingMode::OneWay => {
                (win888 && (is_rst || is_hijack) && !server_replied).then(|| {
                    let kind = if is_rst { "RST" } else { "hijack(PSH/ACK)" };
                    format!(
                        "单向阻断成功：服务器返回有效数据前，NPatch 已注入 {}(窗口888)",
                        kind
                    )
                })
            }
        };

        if let Some(reason) = hit {
            self.verification.mark_blocked(packet, to_client, reason);
        }
    }

    /// 判断本条流是否属于指定阻断模式的「待验证」范围
    ///
    /// 不在范围内的流（例如对 SYN 阻断模式而言一条根本没有 SYN 的流）
    /// 不计入验证统计。
    pub fn verification_in_scope(&self, mode: BlockingMode) -> bool {
        if self.flow_key.protocol() != 6 || self.stats.packet_count == 0 {
            return false;
        }
        match mode {
            // 见过客户端 SYN 即在范围内
            BlockingMode::Syn => self.connection.handshake.client_syn,
            // 三次握手已完成
            BlockingMode::Ack => self.connection.handshake.is_complete(),
            // 握手完成且客户端发出过请求
            BlockingMode::Hijack => {
                self.connection.handshake.is_complete()
                    && self.client_first_data_time.is_some()
            }
            // web 端口流且客户端发出过请求
            BlockingMode::WebScan => {
                self.is_web_flow() && self.client_first_data_time.is_some()
            }
            // 客户端发起过连接（见过 SYN）即在范围内
            BlockingMode::OneWay => self.connection.handshake.client_syn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::flow::FlowKey;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    /// BUG-4：握手计时应在握手完成时被填充。
    #[test]
    fn test_handshake_update_records_times() {
        let mut hs = TcpHandshake::new();
        hs.client_syn = true;
        hs.update(1000); // 首个 SYN，记录 start_time
        assert_eq!(hs.start_time, Some(1000));
        assert!(hs.end_time.is_none(), "握手未完成时不应有 end_time");

        hs.server_syn_ack = true;
        hs.client_ack = true;
        hs.update(1500); // 第三个 ACK，握手完成
        assert_eq!(hs.end_time, Some(1500));
        assert_eq!(hs.duration, Some(500));
        assert_eq!(hs.duration_ms(), Some(0.5));
    }

    /// BUG-8：握手 update() 在时间戳逆序时用 saturating_sub，不应 panic。
    #[test]
    fn test_handshake_update_no_panic_on_reversed_time() {
        let mut hs = TcpHandshake::new();
        hs.client_syn = true;
        hs.update(2000); // start_time = 2000
        hs.server_syn_ack = true;
        hs.client_ack = true;
        hs.update(1000); // end_time = 1000 < start：saturating_sub 得 0，不 panic
        assert_eq!(hs.duration, Some(0));
    }

    /// BUG-2：handle_rst() 应置位 close.reset，且不依赖任何日志开关。
    #[test]
    fn test_handle_rst_sets_close_reset() {
        let key = FlowKey::new(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1234, 80, 6);
        let mut stream = TcpStream::new(key);
        stream.state = TcpState::Established; // RST 仅在已建立等状态下有效

        let rst = PacketInfo {
            timestamp: 5000,
            src_ip: ip(10, 0, 0, 2),
            dst_ip: ip(10, 0, 0, 1),
            src_port: 80,
            dst_port: 1234,
            protocol: 6,
            payload_len: 0,
            tcp_seq: Some(1),
            tcp_ack: Some(2),
            tcp_flags: Some(0x04), // RST
            tcp_window: Some(0),
            ip_ttl: None,
            ip_id: None,
        };

        assert!(stream.handle_rst(&rst), "已建立连接上的 RST 应被判定为有效");
        assert!(stream.connection.close.reset, "close.reset 应被置位");
        assert_eq!(stream.state, TcpState::Reset);
        assert_eq!(stream.rst_time, Some(5000));
        assert!(!stream.connection.close.is_graceful());
    }

    /// BUG-1：任何状态进入 Established 都应记录连接建立时间。
    #[test]
    fn test_update_state_records_established_time() {
        let key = FlowKey::new(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1234, 80, 6);
        let mut stream = TcpStream::new(key);
        stream.state = TcpState::SynReceived; // 正常握手会经过该状态
        stream.update_state(TcpState::Established, 7777);
        assert_eq!(
            stream.connection.established_time,
            Some(7777),
            "从 SynReceived 进入 Established 也应记录建立时间"
        );
    }

    /// BUG-8：connection 持续时间在 last < established 时不应 panic。
    #[test]
    fn test_connection_duration_no_panic_on_reversed_time() {
        let mut conn = ConnectionInfo::new();
        conn.set_established(9000);
        conn.update_activity(8000); // 比建立时间更早
        assert_eq!(conn.duration, Some(0)); // saturating_sub
    }

    // ---- NPatch 阻断验证单元测试 ----

    /// 构造一条流，flow_key 中 10.0.0.1:1234 为客户端、10.0.0.2:80 为服务器。
    fn verify_stream() -> TcpStream {
        let key = FlowKey::new(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1234, 80, 6);
        TcpStream::new(key)
    }

    /// 构造一个 PacketInfo；`to_client=true` 表示 服务器->客户端 方向。
    fn vpkt(
        ts: u64,
        to_client: bool,
        flags: u8,
        window: u16,
        ttl: Option<u8>,
        ip_id: Option<u16>,
        payload_len: usize,
    ) -> PacketInfo {
        let (src_ip, dst_ip, src_port, dst_port) = if to_client {
            (ip(10, 0, 0, 2), ip(10, 0, 0, 1), 80, 1234)
        } else {
            (ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1234, 80)
        };
        PacketInfo {
            timestamp: ts,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: 6,
            payload_len,
            tcp_seq: Some(1),
            tcp_ack: Some(1),
            tcp_flags: Some(flags),
            tcp_window: Some(window),
            ip_ttl: ttl,
            ip_id,
        }
    }

    /// 把流的握手状态直接置为「已完成」。
    fn mark_handshake_complete(stream: &mut TcpStream) {
        stream.connection.handshake.client_syn = true;
        stream.connection.handshake.server_syn_ack = true;
        stream.connection.handshake.client_ack = true;
    }

    #[test]
    fn test_is_npatch_window() {
        assert!(is_npatch_window(Some(888)));
        assert!(is_npatch_window(Some(1776))); // 888 * 2
        assert!(!is_npatch_window(Some(64240)));
        assert!(!is_npatch_window(Some(0)));
        assert!(!is_npatch_window(None));
    }

    #[test]
    fn test_is_npatch_hijack_ip_id() {
        assert!(is_npatch_hijack_ip_id(Some(0x6688)));
        assert!(is_npatch_hijack_ip_id(Some(0x8866))); // 字节交换值
        assert!(!is_npatch_hijack_ip_id(Some(0x0000)));
        assert!(!is_npatch_hijack_ip_id(None));
    }

    #[test]
    fn test_verify_blocking_idempotent() {
        let mut stream = verify_stream();
        mark_handshake_complete(&mut stream);

        // 首个 RST(win888) 命中
        let rst1 = vpkt(1000, true, 0x04, 888, Some(60), Some(0x8866), 0);
        stream.verify_blocking(&rst1, BlockingMode::Ack);
        assert!(stream.verification.blocked);
        assert_eq!(stream.verification.matched_timestamp, Some(1000));

        // 之后的报文不应覆盖首个命中结果
        let rst2 = vpkt(2000, true, 0x04, 888, Some(60), Some(0x8866), 0);
        stream.verify_blocking(&rst2, BlockingMode::Ack);
        assert_eq!(
            stream.verification.matched_timestamp,
            Some(1000),
            "已判定后 verify_blocking 应幂等"
        );
    }

    #[test]
    fn test_verify_hijack_requires_payload() {
        let mut stream = verify_stream();
        mark_handshake_complete(&mut stream);
        stream.client_first_data_time = Some(500);

        // PSH|ACK、win888、朝客户端，但负载为空 —— 不应判为 hijack
        let empty = vpkt(1000, true, 0x18, 888, Some(60), Some(0x8866), 0);
        stream.verify_blocking(&empty, BlockingMode::Hijack);
        assert!(!stream.verification.blocked, "空负载的 PSH/ACK 不应判为 hijack");

        // 带负载则应命中
        let with_payload = vpkt(1100, true, 0x18, 888, Some(60), Some(0x8866), 3);
        stream.verify_blocking(&with_payload, BlockingMode::Hijack);
        assert!(stream.verification.blocked);
        assert_eq!(stream.verification.confidence, Some(HijackConfidence::High));
    }

    #[test]
    fn test_verify_ack_requires_no_server_data() {
        let mut stream = verify_stream();
        mark_handshake_complete(&mut stream);
        // 服务器已经发过真实数据
        stream.server_first_data_time = Some(900);

        let rst = vpkt(1000, true, 0x04, 888, Some(60), Some(0x8866), 0);
        stream.verify_blocking(&rst, BlockingMode::Ack);
        assert!(
            !stream.verification.blocked,
            "服务器已响应后收到的 RST 不应判为 ACK 阻断"
        );
    }

    #[test]
    fn test_verify_blocking_ignores_normal_window() {
        let mut stream = verify_stream();
        mark_handshake_complete(&mut stream);
        // 普通窗口的 RST —— 不是 NPatch 注入
        let rst = vpkt(1000, true, 0x04, 64240, Some(64), Some(0), 0);
        stream.verify_blocking(&rst, BlockingMode::Ack);
        assert!(!stream.verification.blocked, "普通窗口的 RST 不应判为阻断");
    }

    #[test]
    fn test_verify_oneway_blocked_before_server_data() {
        let mut stream = verify_stream();
        mark_handshake_complete(&mut stream);
        // 服务器尚未返回有效数据，收到 NPatch RST(win888)
        let rst = vpkt(1000, true, 0x04, 888, Some(60), Some(0x8866), 0);
        stream.verify_blocking(&rst, BlockingMode::OneWay);
        assert!(stream.verification.blocked, "服务器响应前的 RST 应判为单向阻断成功");
    }

    #[test]
    fn test_verify_oneway_not_blocked_after_server_data() {
        let mut stream = verify_stream();
        mark_handshake_complete(&mut stream);
        // 服务器已返回有效数据
        stream.server_first_data_time = Some(900);
        // 之后才收到 NPatch RST(win888) —— 来晚了
        let rst = vpkt(1000, true, 0x04, 888, Some(60), Some(0x8866), 0);
        stream.verify_blocking(&rst, BlockingMode::OneWay);
        assert!(
            !stream.verification.blocked,
            "服务器已返回有效数据后，RST 不应判为单向阻断成功"
        );
    }

    #[test]
    fn test_detect_server_first_data_excludes_npatch() {
        let mut stream = verify_stream();
        // NPatch hijack 报文（server->client、带负载、窗口888）不应被当成服务器有效数据
        let hijack = vpkt(1000, true, 0x18, 888, Some(60), Some(0x8866), 3);
        stream.detect_server_first_data(&hijack);
        assert!(
            stream.server_first_data_time.is_none(),
            "窗口888 的注入报文不应被记为服务器有效数据"
        );
        // 真实服务器响应（窗口非888）应被记录
        let real = vpkt(1100, true, 0x18, 64240, Some(64), Some(0), 3);
        stream.detect_server_first_data(&real);
        assert_eq!(stream.server_first_data_time, Some(1100));
    }
}