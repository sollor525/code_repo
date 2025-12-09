//! 数据包类型定义
//!
//! 定义了用于表示网络数据包的各种数据结构

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// 数据包头信息
///
/// 包含从PCAP文件中解析出的基本数据包头信息
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketHeader {
    /// 时间戳（秒）
    pub ts_sec: u32,
    /// 时间戳（微秒）
    ts_usec: u32,
    /// 数据包实际长度
    pub caplen: u32,
    /// 数据包原始长度
    pub len: u32,
}

impl PacketHeader {
    /// 创建新的数据包头
    pub fn new(ts_sec: u32, ts_usec: u32, caplen: u32, len: u32) -> Self {
        Self {
            ts_sec,
            ts_usec,
            caplen,
            len,
        }
    }

    /// 获取完整的时间戳（Duration）
    pub fn timestamp(&self) -> Duration {
        Duration::from_secs(self.ts_sec as u64) + Duration::from_micros(self.ts_usec as u64)
    }

    /// 获取时间戳为SystemTime
    pub fn system_time(&self) -> SystemTime {
        UNIX_EPOCH + self.timestamp()
    }
}

/// 协议层类型
///
/// 表示网络协议栈的各个层级
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PacketLayer {
    /// 物理层
    Physical,
    /// 数据链路层（以太网）
    Ethernet,
    /// 网络层（IP）
    Ip,
    /// 传输层（TCP/UDP）
    Transport,
    /// 应用层
    Application,
}

/// 协议类型
///
/// 表示具体的网络协议
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    /// 以太网协议
    Ethernet,
    /// IPv4协议
    Ipv4,
    /// IPv6协议
    Ipv6,
    /// ARP协议
    Arp,
    /// TCP协议
    Tcp,
    /// UDP协议
    Udp,
    /// ICMP协议
    Icmp,
    /// ICMPv6协议
    IcmpV6,
    /// HTTP协议
    Http,
    /// HTTPS协议
    Https,
    /// DNS协议
    Dns,
    /// DHCP协议
    Dhcp,
    /// 其他协议
    Other(u8),
}

/// 网络数据包
///
/// 包含数据包的所有信息，包括头部、负载和解析出的各层协议信息
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packet {
    /// 数据包头信息
    pub header: PacketHeader,
    /// 原始数据包字节
    pub data: Vec<u8>,
    /// 数据包各层信息
    pub layers: Vec<PacketLayer>,
    /// 协议类型链
    pub protocols: Vec<Protocol>,
    /// 源MAC地址（如果存在）
    pub src_mac: Option<[u8; 6]>,
    /// 目的MAC地址（如果存在）
    pub dst_mac: Option<[u8; 6]>,
    /// 源IP地址（如果存在）
    pub src_ip: Option<IpAddr>,
    /// 目的IP地址（如果存在）
    pub dst_ip: Option<IpAddr>,
    /// 源端口（如果存在）
    pub src_port: Option<u16>,
    /// 目的端口（如果存在）
    pub dst_port: Option<u16>,
    /// TCP序列号（如果是TCP包）
    pub tcp_seq: Option<u32>,
    /// TCP确认号（如果是TCP包）
    pub tcp_ack: Option<u32>,
    /// TCP标志位（如果是TCP包）
    pub tcp_flags: Option<TcpFlags>,
    /// TCP窗口大小（如果是TCP包）
    pub tcp_window: Option<u16>,
}

/// TCP标志位
///
/// 表示TCP头部中的各种标志位
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpFlags {
    /// FIN标志（结束连接）
    pub fin: bool,
    /// SYN标志（建立连接）
    pub syn: bool,
    /// RST标志（重置连接）
    pub rst: bool,
    /// PSH标志（推送数据）
    pub psh: bool,
    /// ACK标志（确认）
    pub ack: bool,
    /// URG标志（紧急指针）
    pub urg: bool,
    /// ECE标志（ECN回显）
    pub ece: bool,
    /// CWR标志（拥塞窗口减少）
    pub cwr: bool,
}

impl TcpFlags {
    /// 创建新的TCP标志位
    pub fn new() -> Self {
        Self {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
            ece: false,
            cwr: false,
        }
    }

    /// 从字节数创建TCP标志位
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: (byte & 0x01) != 0,
            syn: (byte & 0x02) != 0,
            rst: (byte & 0x04) != 0,
            psh: (byte & 0x08) != 0,
            ack: (byte & 0x10) != 0,
            urg: (byte & 0x20) != 0,
            ece: (byte & 0x40) != 0,
            cwr: (byte & 0x80) != 0,
        }
    }

    /// 转换为字节数
    pub fn to_byte(&self) -> u8 {
        let mut byte = 0u8;
        if self.fin { byte |= 0x01; }
        if self.syn { byte |= 0x02; }
        if self.rst { byte |= 0x04; }
        if self.psh { byte |= 0x08; }
        if self.ack { byte |= 0x10; }
        if self.urg { byte |= 0x20; }
        if self.ece { byte |= 0x40; }
        if self.cwr { byte |= 0x80; }
        byte
    }

    /// 检查是否是握手包（SYN）
    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack
    }

    /// 检查是否是握手响应包（SYN-ACK）
    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    /// 检查是否是ACK包（非SYN-ACK）
    pub fn is_ack_only(&self) -> bool {
        self.ack && !self.syn
    }

    /// 检查是否是FIN包
    pub fn is_fin(&self) -> bool {
        self.fin
    }

    /// 检查是否是RST包
    pub fn is_rst(&self) -> bool {
        self.rst
    }
}

impl Default for TcpFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl Packet {
    /// 创建新的数据包
    pub fn new(header: PacketHeader, data: Vec<u8>) -> Self {
        Self {
            header,
            data,
            layers: Vec::new(),
            protocols: Vec::new(),
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            tcp_window: None,
        }
    }

    /// 获取数据包时间戳
    pub fn timestamp(&self) -> Duration {
        self.header.timestamp()
    }

    /// 获取数据包长度
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// 检查数据包是否为空
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 检查是否是IPv4数据包
    pub fn is_ipv4(&self) -> bool {
        self.protocols.contains(&Protocol::Ipv4)
    }

    /// 检查是否是IPv6数据包
    pub fn is_ipv6(&self) -> bool {
        self.protocols.contains(&Protocol::Ipv6)
    }

    /// 检查是否是TCP数据包
    pub fn is_tcp(&self) -> bool {
        self.protocols.contains(&Protocol::Tcp)
    }

    /// 检查是否是UDP数据包
    pub fn is_udp(&self) -> bool {
        self.protocols.contains(&Protocol::Udp)
    }

    /// 检查是否是HTTP数据包
    pub fn is_http(&self) -> bool {
        self.protocols.contains(&Protocol::Http)
    }

    /// 检查是否是HTTPS数据包
    pub fn is_https(&self) -> bool {
        self.protocols.contains(&Protocol::Https)
    }

    /// 获取传输层协议号
    ///
    /// 返回传输层协议的协议号：
    /// - TCP: 6
    /// - UDP: 17
    /// - ICMP: 1
    /// - ICMPv6: 58
    /// - 其他: 0
    pub fn protocol(&self) -> u8 {
        if self.protocols.contains(&Protocol::Tcp) {
            6
        } else if self.protocols.contains(&Protocol::Udp) {
            17
        } else if self.protocols.contains(&Protocol::Icmp) {
            1
        } else if self.protocols.contains(&Protocol::IcmpV6) {
            58
        } else {
            0
        }
    }

    /// 获取负载（去掉所有头部后的数据）
    pub fn payload(&self) -> Option<&[u8]> {
        if self.is_tcp() {
            // 简单实现：去掉以太网头(14) + IP头(20或40) + TCP头(20)
            let header_size = if self.is_ipv4() { 54 } else { 74 };
            if self.data.len() > header_size {
                Some(&self.data[header_size..])
            } else {
                None
            }
        } else if self.is_udp() {
            // 简单实现：去掉以太网头 + IP头 + UDP头(8)
            let header_size = if self.is_ipv4() { 42 } else { 62 };
            if self.data.len() > header_size {
                Some(&self.data[header_size..])
            } else {
                None
            }
        } else {
            None
        }
    }

    /// 获取以太网头部
    pub fn ethernet_header(&self) -> Option<&[u8]> {
        if self.data.len() >= 14 {
            Some(&self.data[..14])
        } else {
            None
        }
    }

    /// 获取IP头部
    pub fn ip_header(&self) -> Option<&[u8]> {
        if self.data.len() >= 14 {
            let ip_start = 14;
            if self.data.len() > ip_start {
                // 简单的IP版本检测
                let version = (self.data[ip_start] >> 4) & 0x0F;
                let header_len = match version {
                    4 => {
                        let ihl = self.data[ip_start] & 0x0F;
                        (ihl as usize) * 4
                    }
                    6 => 40,
                    _ => return None,
                };

                if self.data.len() >= ip_start + header_len {
                    Some(&self.data[ip_start..ip_start + header_len])
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// 获取TCP头部
    pub fn tcp_header(&self) -> Option<&[u8]> {
        if let Some(ip_header) = self.ip_header() {
            let ip_start = 14;
            let ip_header_len = ip_header.len();
            let tcp_start = ip_start + ip_header_len;

            if self.data.len() > tcp_start + 20 {
                // TCP头部最小20字节
                let tcp_header_len = ((self.data[tcp_start + 12] >> 4) & 0x0F) as usize * 4;
                if self.data.len() >= tcp_start + tcp_header_len {
                    Some(&self.data[tcp_start..tcp_start + tcp_header_len])
                } else {
                    Some(&self.data[tcp_start..])
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// 获取UDP头部
    pub fn udp_header(&self) -> Option<&[u8]> {
        if let Some(ip_header) = self.ip_header() {
            let ip_start = 14;
            let ip_header_len = ip_header.len();
            let udp_start = ip_start + ip_header_len;

            if self.data.len() >= udp_start + 8 {
                // UDP头部固定8字节
                Some(&self.data[udp_start..udp_start + 8])
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl From<Protocol> for u8 {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Ethernet => 1,
            Protocol::Ipv4 => 2,
            Protocol::Ipv6 => 3,
            Protocol::Arp => 4,
            Protocol::Tcp => 5,
            Protocol::Udp => 6,
            Protocol::Icmp => 7,
            Protocol::IcmpV6 => 8,
            Protocol::Http => 9,
            Protocol::Https => 10,
            Protocol::Dns => 11,
            Protocol::Dhcp => 12,
            Protocol::Other(val) => val,
        }
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            header: PacketHeader::new(0, 0, 0, 0),
            data: Vec::new(),
            layers: Vec::new(),
            protocols: Vec::new(),
            src_mac: None,
            dst_mac: None,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            tcp_seq: None,
            tcp_ack: None,
            tcp_flags: None,
            tcp_window: None,
        }
    }
}