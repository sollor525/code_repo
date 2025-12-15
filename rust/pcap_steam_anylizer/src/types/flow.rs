//! 流类型定义
//!
//! 定义了用于表示网络流的各种数据结构，包括流键值、流方向等

use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// 流方向
///
/// 表示数据流的方向
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowDirection {
    /// 客户端到服务器
    ClientToServer,
    /// 服务器到客户端
    ServerToClient,
    /// 未知方向
    Unknown,
}

/// 流键值
///
/// 使用五元组（源IP、目的IP、源端口、目的端口、协议）唯一标识一个流
/// 为了确保同一个连接的双向数据包具有相同的FlowKey，我们在创建时会对IP和端口进行排序
/// 注意：ip1_is_client 字段不计入哈希和相等性比较，以确保双向流有相同的键值
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowKey {
    /// IP地址1（排序后较小的IP）
    ip1: IpAddr,
    /// IP地址2（排序后较大的IP）
    ip2: IpAddr,
    /// 端口1（与ip1对应的端口）
    port1: u16,
    /// 端口2（与ip2对应的端口）
    port2: u16,
    /// 协议类型
    protocol: u8,
    /// 标识ip1:port1是否是客户端（用于后续判断流方向）
    ip1_is_client: bool,
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.ip1 == other.ip1
            && self.ip2 == other.ip2
            && self.port1 == other.port1
            && self.port2 == other.port2
            && self.protocol == other.protocol
    }
}

impl Eq for FlowKey {}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip1.hash(state);
        self.ip2.hash(state);
        self.port1.hash(state);
        self.port2.hash(state);
        self.protocol.hash(state);
    }
}

impl FlowKey {
    /// 创建新的流键值
    ///
    /// 内部会自动对IP进行排序，确保双向流的键值相同
    /// 注意：端口和客户端/服务器关系的确定基于源IP/端口
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        // 只对IP地址进行排序，端口保持原始顺序
        if src_ip < dst_ip {
            Self {
                ip1: src_ip,
                ip2: dst_ip,
                port1: src_port,
                port2: dst_port,
                protocol,
                ip1_is_client: true, // ip1是源IP，所以它是客户端
            }
        } else if src_ip > dst_ip {
            Self {
                ip1: dst_ip,
                ip2: src_ip,
                port1: dst_port,
                port2: src_port,
                protocol,
                ip1_is_client: false, // ip1是目的IP，所以它不是客户端
            }
        } else {
            // IP地址相同，这种情况很少见，保持原有逻辑
            Self {
                ip1: src_ip,
                ip2: dst_ip,
                port1: src_port,
                port2: dst_port,
                protocol,
                ip1_is_client: true,
            }
        }
    }

    /// 获取源IP地址
    pub fn src_ip(&self) -> &IpAddr {
        if self.ip1_is_client {
            &self.ip1
        } else {
            &self.ip2
        }
    }

    /// 获取目的IP地址
    pub fn dst_ip(&self) -> &IpAddr {
        if self.ip1_is_client {
            &self.ip2
        } else {
            &self.ip1
        }
    }

    /// 获取源端口
    pub fn src_port(&self) -> u16 {
        if self.ip1_is_client {
            self.port1
        } else {
            self.port2
        }
    }

    /// 获取目的端口
    pub fn dst_port(&self) -> u16 {
        if self.ip1_is_client {
            self.port2
        } else {
            self.port1
        }
    }

    /// 获取协议类型
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// 检查是否是IPv4流
    pub fn is_ipv4(&self) -> bool {
        self.ip1.is_ipv4() && self.ip2.is_ipv4()
    }

    /// 检查是否是IPv6流
    pub fn is_ipv6(&self) -> bool {
        self.ip1.is_ipv6() && self.ip2.is_ipv6()
    }

    /// 检查是否是TCP流
    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    /// 检查是否是UDP流
    pub fn is_udp(&self) -> bool {
        self.protocol == 17
    }

    /// 获取协议名称
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            58 => "ICMPv6",
            _ => "Other",
        }
    }

    /// 判断给定方向相对于当前流的方向
    pub fn get_direction(&self, ip: &IpAddr, port: u16) -> FlowDirection {
        // 检查是否是客户端到服务器方向
        let is_client_to_server = if self.ip1_is_client {
            // ip1:port1 是客户端（原始源）
            ip == &self.ip1 && port == self.port1
        } else {
            // ip2:port2 是客户端（原始源）
            ip == &self.ip2 && port == self.port2
        };

        if is_client_to_server {
            FlowDirection::ClientToServer
        } else if (ip == &self.ip1 && port == self.port1) || (ip == &self.ip2 && port == self.port2) {
            FlowDirection::ServerToClient
        } else {
            FlowDirection::Unknown
        }
    }

    /// 获取反向流键值
    pub fn reverse(&self) -> Self {
        Self {
            ip1: self.ip1,
            ip2: self.ip2,
            port1: self.port2,
            port2: self.port1,
            protocol: self.protocol,
            ip1_is_client: !self.ip1_is_client,
        }
    }
}


impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip(),
            self.src_port(),
            self.dst_ip(),
            self.dst_port(),
            self.protocol_name()
        )
    }
}

/// 流统计信息
///
/// 记录流的基本统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStats {
    /// 数据包总数
    pub packet_count: u64,
    /// 字节总数
    pub byte_count: u64,
    /// 客户端到服务器的数据包数
    pub c2s_packet_count: u64,
    /// 服务器到客户端的数据包数
    pub s2c_packet_count: u64,
    /// 客户端到服务器的字节数
    pub c2s_byte_count: u64,
    /// 服务器到客户端的字节数
    pub s2c_byte_count: u64,
    /// 第一个数据包的时间戳
    pub first_packet_time: Option<u64>,
    /// 最后一个数据包的时间戳
    pub last_packet_time: Option<u64>,
    /// 平均数据包大小
    pub avg_packet_size: f64,
    /// 最大数据包大小
    pub max_packet_size: u32,
    /// 最小数据包大小
    pub min_packet_size: u32,
}

impl FlowStats {
    /// 创建新的流统计信息
    pub fn new() -> Self {
        Self {
            packet_count: 0,
            byte_count: 0,
            c2s_packet_count: 0,
            s2c_packet_count: 0,
            c2s_byte_count: 0,
            s2c_byte_count: 0,
            first_packet_time: None,
            last_packet_time: None,
            avg_packet_size: 0.0,
            max_packet_size: 0,
            min_packet_size: u32::MAX,
        }
    }

    /// 更新统计信息
    pub fn update(&mut self, bytes: usize, direction: FlowDirection, timestamp: u64) {
        self.packet_count += 1;
        self.byte_count += bytes as u64;

        // 更新时间戳
        if self.first_packet_time.is_none() {
            self.first_packet_time = Some(timestamp);
        }
        self.last_packet_time = Some(timestamp);

        // 更新大小统计
        let bytes_u32 = bytes as u32;
        if bytes_u32 > self.max_packet_size {
            self.max_packet_size = bytes_u32;
        }
        if bytes_u32 < self.min_packet_size {
            self.min_packet_size = bytes_u32;
        }

        // 更新方向统计
        match direction {
            FlowDirection::ClientToServer => {
                self.c2s_packet_count += 1;
                self.c2s_byte_count += bytes as u64;
            }
            FlowDirection::ServerToClient => {
                self.s2c_packet_count += 1;
                self.s2c_byte_count += bytes as u64;
            }
            FlowDirection::Unknown => {}
        }

        // 更新平均包大小
        if self.packet_count > 0 {
            self.avg_packet_size = self.byte_count as f64 / self.packet_count as f64;
        }
    }

    /// 获取流持续时间（微秒）
    pub fn duration(&self) -> Option<u64> {
        match (self.first_packet_time, self.last_packet_time) {
            (Some(first), Some(last)) => Some(last - first),
            _ => None,
        }
    }

    /// 获取流持续时间（秒）
    pub fn duration_seconds(&self) -> Option<f64> {
        self.duration().map(|micros| micros as f64 / 1_000_000.0)
    }

    /// 获取每秒平均数据包数
    pub fn packets_per_second(&self) -> f64 {
        match self.duration_seconds() {
            Some(duration) if duration > 0.0 => self.packet_count as f64 / duration,
            _ => 0.0,
        }
    }

    /// 获取每秒平均字节数
    pub fn bytes_per_second(&self) -> f64 {
        match self.duration_seconds() {
            Some(duration) if duration > 0.0 => self.byte_count as f64 / duration,
            _ => 0.0,
        }
    }

    /// 获取每秒平均位数
    pub fn bits_per_second(&self) -> f64 {
        self.bytes_per_second() * 8.0
    }

    /// 重置统计信息
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for FlowStats {
    fn default() -> Self {
        Self::new()
    }
}

/// 五元组
///
/// 未排序的原始五元组信息
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FiveTuple {
    /// 源IP地址
    pub src_ip: IpAddr,
    /// 目的IP地址
    pub dst_ip: IpAddr,
    /// 源端口
    pub src_port: u16,
    /// 目的端口
    pub dst_port: u16,
    /// 协议类型
    pub protocol: u8,
}

impl FiveTuple {
    /// 创建新的五元组
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// 转换为FlowKey
    pub fn to_flow_key(&self) -> FlowKey {
        FlowKey::new(self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
    }

    /// 获取反向五元组
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// 检查是否是本地流（IP地址在私有范围）
    pub fn is_local(&self) -> bool {
        fn is_private_ip(ip: &IpAddr) -> bool {
            match ip {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    (octets[0] == 10) ||
                    (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) ||
                    (octets[0] == 192 && octets[1] == 168) ||
                    (octets[0] == 127) // loopback
                }
                IpAddr::V6(ipv6) => {
                    // IPv6 loopback (::1) or private (fc00::/7)
                    ipv6.is_loopback() || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                }
            }
        }

        is_private_ip(&self.src_ip) && is_private_ip(&self.dst_ip)
    }

    }

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            match self.protocol {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                58 => "ICMPv6",
                _ => "Other",
            }
        )
    }
}

/// 流标签
///
/// 用于标记流的特征或分类
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowLabel {
    /// HTTP流量
    Http,
    /// HTTPS流量
    Https,
    /// DNS流量
    Dns,
    /// SSH流量
    Ssh,
    /// FTP流量
    Ftp,
    /// 电子邮件流量
    Email,
    /// 视频流量
    Video,
    /// 音频流量
    Audio,
    /// 游戏流量
    Gaming,
    /// P2P流量
    P2P,
    /// 恶意流量
    Malicious,
    /// 其他流量
    Other(String),
}

impl FlowLabel {
    /// 从端口号推测协议
    pub fn from_port(port: u16) -> Option<Self> {
        match port {
            20 | 21 => Some(Self::Ftp),
            22 => Some(Self::Ssh),
            25 | 587 => Some(Self::Email),
            53 => Some(Self::Dns),
            80 => Some(Self::Http),
            110 => Some(Self::Email), // POP3
            143 => Some(Self::Email), // IMAP
            443 => Some(Self::Https),
            993 => Some(Self::Email), // IMAPS
            995 => Some(Self::Email), // POP3S
            5060 | 5061 => Some(Self::Other("SIP".to_string())),
            _ => None,
        }
    }
}

impl fmt::Display for FlowLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http => write!(f, "HTTP"),
            Self::Https => write!(f, "HTTPS"),
            Self::Dns => write!(f, "DNS"),
            Self::Ssh => write!(f, "SSH"),
            Self::Ftp => write!(f, "FTP"),
            Self::Email => write!(f, "Email"),
            Self::Video => write!(f, "Video"),
            Self::Audio => write!(f, "Audio"),
            Self::Gaming => write!(f, "Gaming"),
            Self::P2P => write!(f, "P2P"),
            Self::Malicious => write!(f, "Malicious"),
            Self::Other(name) => write!(f, "{}", name),
        }
    }
}