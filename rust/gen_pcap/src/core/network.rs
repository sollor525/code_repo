// 网络层基础类型

use std::net::Ipv4Addr;
use std::str::FromStr;
use rand::Rng;

// IP地址范围结构体
#[derive(Debug, Clone)]
pub struct IpRange {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl IpRange {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self { start, end }
    }

    pub fn from_string(range_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let clean_str = range_str.trim().to_lowercase();

        if clean_str == "random" {
            // 只使用合法的单播IP地址范围
            // 排除: 0.0.0.0/8 (保留地址), 127.0.0.0/8 (环回), 224.0.0.0/4 (组播), 240.0.0.0/4 (保留)
            // 使用: 1.0.0.0 - 223.255.255.255

            // 生成随机合法的单播IP地址
            let mut rng = rand::thread_rng();

            // 随机选择一个A、B、C类网络
            let first_octet = match rng.gen_range(0..3) {
                0 => rng.gen_range(1..127),    // A类: 1.0.0.0 - 126.255.255.255
                1 => rng.gen_range(128..192), // B类: 128.0.0.0 - 191.255.255.255
                _ => rng.gen_range(192..224), // C类: 192.0.0.0 - 223.255.255.255
            };

            let ip = Ipv4Addr::new(
                first_octet,
                rng.gen_range(0..=255),
                rng.gen_range(0..=255),
                rng.gen_range(1..=255) // 确保最后一个字节不为0（避免网络地址）
            );

            Ok(Self::new(ip, ip))
        } else if clean_str.contains('-') {
            let parts: Vec<&str> = clean_str.split('-').collect();
            if parts.len() != 2 {
                return Err("Invalid IP range format".into());
            }
            let start = Ipv4Addr::from_str(parts[0].trim())?;
            let end = Ipv4Addr::from_str(parts[1].trim())?;
            Ok(Self::new(start, end))
        } else {
            let ip = Ipv4Addr::from_str(&clean_str)?;
            Ok(Self::new(ip, ip))
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let start_u32: u32 = self.start.into();
        let end_u32: u32 = self.end.into();
        let ip_u32: u32 = ip.into();
        ip_u32 >= start_u32 && ip_u32 <= end_u32
    }

    pub fn random_ip(&self) -> Ipv4Addr {
        let start_u32: u32 = self.start.into();
        let end_u32: u32 = self.end.into();
        let mut rng = rand::thread_rng();
        let random_u32 = rng.gen_range(start_u32..=end_u32);
        Ipv4Addr::from(random_u32)
    }

    pub fn count(&self) -> u64 {
        let start_u32: u32 = self.start.into();
        let end_u32: u32 = self.end.into();
        if end_u32 >= start_u32 {
            (end_u32 - start_u32) as u64 + 1
        } else {
            0
        }
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

// 网络连接信息 - 只关心网络层
#[derive(Debug, Clone)]
pub struct NetworkConnection {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl NetworkConnection {
    pub fn new(src_mac: [u8; 6], dst_mac: [u8; 6],
               src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
               src_port: u16, dst_port: u16) -> Self {
        Self {
            src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port
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