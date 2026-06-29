// 网络层基础类型

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use rand::Rng;

// IP版本枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

// IP地址范围枚举 - 支持 IPv4 和 IPv6
#[derive(Debug, Clone)]
pub enum IpRange {
    V4 { start: Ipv4Addr, end: Ipv4Addr },
    V6 { start: Ipv6Addr, end: Ipv6Addr },
}

impl IpRange {
    pub fn new_v4(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self::V4 { start, end }
    }

    pub fn new_v6(start: Ipv6Addr, end: Ipv6Addr) -> Self {
        Self::V6 { start, end }
    }

    pub fn from_string(range_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let clean_str = range_str.trim().to_lowercase();

        if clean_str == "random" {
            // 向后兼容：random 默认生成 IPv4
            Ok(Self::random_ipv4())
        } else if clean_str == "random-v6" {
            Ok(Self::random_ipv6())
        } else if clean_str.contains('-') {
            // 处理范围
            let parts: Vec<&str> = clean_str.split('-').collect();
            if parts.len() != 2 {
                return Err("无效的IP范围格式".into());
            }

            // 尝试解析 IPv4
            if let (Ok(start_v4), Ok(end_v4)) = (
                parts[0].trim().parse::<Ipv4Addr>(),
                parts[1].trim().parse::<Ipv4Addr>()
            ) {
                return Ok(Self::V4 { start: start_v4, end: end_v4 });
            }

            // 尝试解析 IPv6
            if let (Ok(start_v6), Ok(end_v6)) = (
                parts[0].trim().parse::<Ipv6Addr>(),
                parts[1].trim().parse::<Ipv6Addr>()
            ) {
                return Ok(Self::V6 { start: start_v6, end: end_v6 });
            }

            Err("无效的IP地址格式".into())
        } else {
            // 单个 IP 地址
            if let Ok(ip_v4) = clean_str.parse::<Ipv4Addr>() {
                return Ok(Self::V4 { start: ip_v4, end: ip_v4 });
            }

            if let Ok(ip_v6) = clean_str.parse::<Ipv6Addr>() {
                return Ok(Self::V6 { start: ip_v6, end: ip_v6 });
            }

            Err("无效的IP地址格式".into())
        }
    }

    /// 检查 IP 版本
    pub fn ip_version(&self) -> IpVersion {
        match self {
            IpRange::V4 { .. } => IpVersion::V4,
            IpRange::V6 { .. } => IpVersion::V6,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (IpRange::V4 { start, end }, IpAddr::V4(ip_v4)) => {
                let start_u32: u32 = (*start).into();
                let end_u32: u32 = (*end).into();
                let ip_u32: u32 = ip_v4.into();
                ip_u32 >= start_u32 && ip_u32 <= end_u32
            }
            (IpRange::V6 { start, end }, IpAddr::V6(ip_v6)) => {
                let start_u128: u128 = (*start).into();
                let end_u128: u128 = (*end).into();
                let ip_u128: u128 = ip_v6.into();
                ip_u128 >= start_u128 && ip_u128 <= end_u128
            }
            _ => false,
        }
    }

    pub fn random_ip(&self) -> IpAddr {
        match self {
            IpRange::V4 { start, end } => {
                let start_u32: u32 = (*start).into();
                let end_u32: u32 = (*end).into();
                let mut rng = rand::thread_rng();
                let random_u32 = rng.gen_range(start_u32..=end_u32);
                IpAddr::V4(Ipv4Addr::from(random_u32))
            }
            IpRange::V6 { start, end } => {
                let start_u128: u128 = (*start).into();
                let end_u128: u128 = (*end).into();
                let mut rng = rand::thread_rng();
                let random_u128 = rng.gen_range(start_u128..=end_u128);
                IpAddr::V6(Ipv6Addr::from(random_u128))
            }
        }
    }

    pub fn count(&self) -> u64 {
        match self {
            IpRange::V4 { start, end } => {
                let start_u32: u32 = (*start).into();
                let end_u32: u32 = (*end).into();
                if end_u32 >= start_u32 {
                    (end_u32 - start_u32) as u64 + 1
                } else {
                    0
                }
            }
            IpRange::V6 { start, end } => {
                let start_u128: u128 = (*start).into();
                let end_u128: u128 = (*end).into();
                if end_u128 >= start_u128 {
                    // 对于大的 IPv6 范围，限制返回值
                    let count = end_u128 - start_u128 + 1;
                    if count > u64::MAX as u128 {
                        u64::MAX
                    } else {
                        count as u64
                    }
                } else {
                    0
                }
            }
        }
    }

    /// 生成随机 IPv4 地址（向后兼容）
    fn random_ipv4() -> Self {
        let mut rng = rand::thread_rng();
        let first_octet = match rng.gen_range(0..3) {
            0 => rng.gen_range(1..127),
            1 => rng.gen_range(128..192),
            _ => rng.gen_range(192..224),
        };
        let ip = Ipv4Addr::new(
            first_octet,
            rng.gen_range(0..=255),
            rng.gen_range(0..=255),
            rng.gen_range(1..=255)
        );
        Self::V4 { start: ip, end: ip }
    }

    /// 生成随机 IPv6 地址（全局单播地址 2000::/3）
    fn random_ipv6() -> Self {
        let mut rng = rand::thread_rng();
        let segments: [u16; 8] = [
            0x2000 + rng.gen_range(0..0x1000),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
            rng.gen(),
        ];
        let ip = Ipv6Addr::new(segments[0], segments[1], segments[2], segments[3],
                               segments[4], segments[5], segments[6], segments[7]);
        Self::V6 { start: ip, end: ip }
    }
}

// 端口范围结构体
#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub fn from_string(range_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // 处理逗号分隔的端口列表 - 选择第一个端口或第一个范围
        let clean_str = range_str.split(',').next().unwrap_or(range_str).trim().to_lowercase();

        if clean_str == "random" {
            // 只使用合法端口范围 (1-65535，排除系统保留端口0和部分高端口)
            // 但在实际应用中，通常使用 1024-49151 (注册端口) 和 49152-65535 (动态/私有端口)
            let mut rng = rand::thread_rng();

            // 80%概率使用动态端口，20%概率使用注册端口
            let port = if rng.gen_range(0..100) < 80 {
                // 动态/私有端口: 49152-65535
                rng.gen_range(49152..=65535)
            } else {
                // 注册端口: 1024-49151
                rng.gen_range(1024..=49151)
            };

            Ok(Self::new(port, port))
        } else if clean_str.contains('-') {
            let parts: Vec<&str> = clean_str.split('-').collect();
            if parts.len() != 2 {
                return Err("Invalid port range format".into());
            }
            let start = parts[0].trim().parse::<u16>()?;
            let end = parts[1].trim().parse::<u16>()?;
            Ok(Self::new(start, end))
        } else {
            let port = clean_str.parse::<u16>()?;
            Ok(Self::new(port, port))
        }
    }

    pub fn random_port(&self) -> u16 {
        let mut rng = rand::thread_rng();
        rng.gen_range(self.start..=self.end)
    }

    pub fn count(&self) -> u32 {
        if self.end >= self.start {
            (self.end - self.start + 1) as u32
        } else {
            0
        }
    }
}

// 网络连接信息 - 支持 IPv4 和 IPv6
#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl NetworkConnection {
    pub fn new(src_mac: [u8; 6], dst_mac: [u8; 6],
               src_ip: IpAddr, dst_ip: IpAddr,
               src_port: u16, dst_port: u16) -> Self {
        Self {
            src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port
        }
    }

    /// 检查 IP 版本一致性
    pub fn validate_ip_version(&self) -> Result<(), String> {
        match (&self.src_ip, &self.dst_ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) => Ok(()),
            (IpAddr::V6(_), IpAddr::V6(_)) => Ok(()),
            _ => Err("源IP和目标IP必须为同一版本（同为IPv4或同为IPv6）".to_string())
        }
    }

    /// 获取 IP 版本
    pub fn ip_version(&self) -> IpVersion {
        match self.src_ip {
            IpAddr::V4(_) => IpVersion::V4,
            IpAddr::V6(_) => IpVersion::V6,
        }
    }

    pub fn reverse(&self) -> Self {
        Self {
            src_mac: self.dst_mac,
            dst_mac: self.src_mac,
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}
