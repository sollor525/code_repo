//! 数据包解析模块
//!
//! 提供高效的网络数据包解析功能，包括：
//! - 以太网帧解析
//! - IP 头部解析
//! - TCP 头部解析
//! - 数据包验证

use core::mem;

use crate::maps::*;

/// 以太网头部
#[repr(C)]
pub struct ethhdr {
    pub h_dest: [u8; 6],       // 目的 MAC
    pub h_source: [u8; 6],     // 源 MAC
    pub h_proto: u16,          // 以太网类型
}

/// IP 头部
#[repr(C)]
pub struct iphdr {
    pub version_ihl: u8,       // 版本(4位) + 头长度(4位)
    pub tos: u8,               // 服务类型
    pub tot_len: u16,          // 总长度
    pub id: u16,               // 标识
    pub frag_off: u16,         // 片偏移
    pub ttl: u8,               // 生存时间
    pub protocol: u8,          // 协议类型
    pub check: u16,            // 校验和
    pub saddr: u32,            // 源地址
    pub daddr: u32,            // 目的地址
}

impl iphdr {
    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.version_ihl >> 4
    }

    #[inline(always)]
    pub fn ihl(&self) -> u8 {
        (self.version_ihl & 0x0F) << 2
    }
}

/// TCP 头部
#[repr(C)]
pub struct tcphdr {
    pub source: u16,           // 源端口
    pub dest: u16,             // 目的端口
    pub seq: u32,              // 序列号
    pub ack_seq: u32,          // 确认号
    pub data_offset_res: u8,   // 数据偏移（4位）+ 保留（4位）
    pub flags: u8,             // 标志位（8位）
    pub window: u16,           // 窗口大小
    pub check: u16,            // 校验和
    pub urg_ptr: u16,          // 紧急指针
}

impl tcphdr {
    #[inline(always)]
    pub fn doff(&self) -> u8 {
        // 高 4 位是数据偏移（以 32 位字为单位）
        ((self.data_offset_res >> 4) & 0x0F) << 2
    }

    #[inline(always)]
    pub fn fin(&self) -> u16 {
        (self.flags & 0x01) as u16
    }

    #[inline(always)]
    pub fn syn(&self) -> u16 {
        ((self.flags >> 1) & 0x01) as u16
    }

    #[inline(always)]
    pub fn rst(&self) -> u16 {
        ((self.flags >> 2) & 0x01) as u16
    }

    #[inline(always)]
    pub fn psh(&self) -> u16 {
        ((self.flags >> 3) & 0x01) as u16
    }

    #[inline(always)]
    pub fn ack(&self) -> u16 {
        ((self.flags >> 4) & 0x01) as u16
    }

    #[inline(always)]
    pub fn urg(&self) -> u16 {
        ((self.flags >> 5) & 0x01) as u16
    }

    #[inline(always)]
    pub fn ece(&self) -> u16 {
        ((self.flags >> 6) & 0x01) as u16
    }

    #[inline(always)]
    pub fn cwr(&self) -> u16 {
        ((self.flags >> 7) & 0x01) as u16
    }

    #[inline(always)]
    pub fn flags_value(&self) -> u8 {
        self.flags
    }

    // TCP 标志常量
    pub const FIN_FLAG: u16 = 0x001;
    pub const SYN_FLAG: u16 = 0x002;
    pub const RST_FLAG: u16 = 0x004;
    pub const PSH_FLAG: u16 = 0x008;
    pub const ACK_FLAG: u16 = 0x010;
    pub const URG_FLAG: u16 = 0x020;
    pub const ECE_FLAG: u16 = 0x040;
    pub const CWR_FLAG: u16 = 0x080;
}

/// 解析数据包的详细信息
pub struct PacketParser {
    data: *const u8,
    data_end: *const u8,
}

impl PacketParser {
    /// 创建新的数据包解析器
    #[inline(always)]
    pub fn new(data: *const u8, data_end: *const u8) -> Self {
        Self { data, data_end }
    }

    /// 检查指针是否在有效范围内
    #[inline(always)]
    fn check_bounds(&self, ptr: *const u8, size: usize) -> bool {
        ptr >= self.data &&
        (ptr as usize + size) <= (self.data_end as usize)
    }

    /// 解析以太网头部
    #[inline(always)]
    pub fn parse_ethernet(&self) -> Option<&ethhdr> {
        let eth = self.data as *const ethhdr;
        if !self.check_bounds(eth as *const u8, mem::size_of::<ethhdr>()) {
            return None;
        }

        // 检查以太网类型
        let eth_hdr = unsafe { &*eth };
        match u16::from_be(eth_hdr.h_proto) {
            ETH_P_IP => Some(eth_hdr),
            _ => None,
        }
    }

    /// 解析 IP 头部
    #[inline(always)]
    pub fn parse_ip(&self, eth: &ethhdr) -> Option<&iphdr> {
        let ip = unsafe {
            (eth as *const ethhdr).add(1) as *const iphdr
        };

        if !self.check_bounds(ip as *const u8, mem::size_of::<iphdr>()) {
            return None;
        }

        let ip_hdr = unsafe { &*ip };

        // 验证 IP 版本
        if ip_hdr.version() != 4 {
            return None;
        }

        // 验证头部长度
        let ihl = ip_hdr.ihl() as usize;
        if ihl < 20 || ihl > 60 {
            return None;
        }

        Some(ip_hdr)
    }

    /// 解析 TCP 头部
    #[inline(always)]
    pub fn parse_tcp(&self, ip: &iphdr) -> Option<&tcphdr> {
        // 检查协议类型
        if ip.protocol != IPPROTO_TCP {
            return None;
        }

        let tcp = unsafe {
            (ip as *const iphdr).add((ip.ihl() / 4) as usize) as *const tcphdr
        };

        if !self.check_bounds(tcp as *const u8, mem::size_of::<tcphdr>()) {
            return None;
        }

        let tcp_hdr = unsafe { &*tcp };

        // 验证 TCP 头部长度
        let doff = tcp_hdr.doff() as usize;
        if doff < 20 || doff > 60 {
            return None;
        }

        // 验证数据包完整性
        let total_len = u16::from_be(ip.tot_len) as usize;
        let header_len = (ip.ihl() as usize) + doff;
        if total_len < header_len {
            return None;
        }

        Some(tcp_hdr)
    }

    /// 获取 TCP 负载
    #[inline(always)]
    pub fn get_tcp_payload(&self, ip: &iphdr, tcp: &tcphdr) -> Option<(*const u8, u16)> {
        let total_len = u16::from_be(ip.tot_len) as usize;
        let header_len = (ip.ihl() as usize) + (tcp.doff() as usize);

        if total_len <= header_len {
            return None;
        }

        let payload = unsafe {
            (tcp as *const tcphdr).add((tcp.doff() / 4) as usize) as *const u8
        };

        let payload_len = (total_len - header_len) as u16;

        if !self.check_bounds(payload, payload_len as usize) {
            return None;
        }

        Some((payload, payload_len))
    }

    /// 计算数据包的哈希值
    #[inline(always)]
    pub fn calculate_packet_hash(&self, ip: &iphdr, tcp: &tcphdr) -> u64 {
        // 使用五元组计算哈希
        let mut hash = 0u64;

        hash ^= u64::from(ip.saddr);
        hash ^= u64::from(ip.daddr) << 32;
        hash ^= u64::from(tcp.source) << 16;
        hash ^= u64::from(tcp.dest) << 24;
        hash ^= u64::from(tcp.seq) << 32;
        hash ^= u64::from(tcp.ack_seq) << 40;

        hash
    }

    /// 检查是否为重复数据包
    #[inline(always)]
    pub fn is_duplicate(&self, _ip: &iphdr, _tcp: &tcphdr, _packet_hash: u64) -> bool {
        // 这里可以实现简单的重复包检测
        // 例如基于序列号和时间戳的判断
        false  // 暂时返回 false
    }

    /// 验证 TCP 校验和
    #[inline(always)]
    pub fn verify_tcp_checksum(&self, _ip: &iphdr, _tcp: &tcphdr) -> bool {
        // 由于 eBPF 验证器限制，这里暂时跳过校验和验证
        // 在生产环境中应该实现完整的校验和验证
        true
    }
}

/// 快速数据包解析函数
///
/// 用于性能关键路径，只解析必要的信息
#[inline(always)]
pub fn fast_parse_packet(data: *const u8, data_end: *const u8) -> Option<PacketInfo> {
    let parser = PacketParser::new(data, data_end);

    // 快速解析以太网头部
    let eth = parser.parse_ethernet()?;

    // 快速解析 IP 头部
    let ip = parser.parse_ip(eth)?;

    // 只处理 TCP
    if ip.protocol != IPPROTO_TCP {
        return None;
    }

    // 快速解析 TCP 头部
    let tcp = parser.parse_tcp(ip)?;

    // 构建数据包信息（保持网络字节序用于会话 key）
    let mut packet_info = PacketInfo::default();
    packet_info.src_ip = ip.saddr;
    packet_info.dst_ip = ip.daddr;
    packet_info.src_port = tcp.source;  // 保持网络字节序
    packet_info.dst_port = tcp.dest;    // 保持网络字节序
    packet_info.ip_proto = ip.protocol;
    packet_info.ip_header_len = ip.ihl();  // 保存 IP 头部长度
    packet_info.timestamp = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
    packet_info.packet_size = u16::from_be(ip.tot_len) as u32;

    // 计算负载大小
    if let Some((_, payload_size)) = parser.get_tcp_payload(ip, tcp) {
        packet_info.payload_size = payload_size;
    }

    Some(packet_info)
}

/// 提取五元组信息
#[inline(always)]
pub fn extract_five_tuple(packet_info: &PacketInfo) -> (u32, u32, u16, u16, u8) {
    (
        packet_info.src_ip,
        packet_info.dst_ip,
        packet_info.src_port,
        packet_info.dst_port,
        packet_info.ip_proto,
    )
}

/// 检查端口是否在扫描范围内
#[inline(always)]
pub fn is_scan_port(port: u16) -> bool {
    // 常见扫描端口范围
    (port >= 1 && port <= 1024) ||      // 系统端口
    (port >= 3000 && port <= 9000) ||   // 应用端口
    (port >= 8000 && port <= 8080) ||   // Web 端口
    (port >= 3306 && port <= 3306) ||   // MySQL
    (port >= 5432 && port <= 5432) ||   // PostgreSQL
    (port >= 6379 && port <= 6379)      // Redis
}