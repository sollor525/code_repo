use std::net::{Ipv4Addr, Ipv6Addr};

pub struct NetworkUtils {
    // 移除了 GUI 状态，现在只是一个无状态的工具类
}

impl NetworkUtils {
    pub fn new() -> Self {
        Self {}
    }

    // IP地址转换函数
    pub fn ip_to_network_order(&self, ip_str: &str) -> String {
        if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
            let octets = ipv4.octets();
            return format!("0x{:02X}{:02X}{:02X}{:02X}", octets[0], octets[1], octets[2], octets[3]);
        } else if let Ok(ipv6) = ip_str.parse::<Ipv6Addr>() {
            let segments = ipv6.segments();
            return format!("0x{:04X}{:04X}{:04X}{:04X}{:04X}{:04X}{:04X}{:04X}",
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7]);
        }
        "无效的IP地址格式".to_string()
    }

    pub fn ip_to_host_order(&self, ip_str: &str) -> String {
        // 处理十六进制格式
        if ip_str.starts_with("0x") || ip_str.starts_with("0X") {
            let hex_str = ip_str.trim_start_matches("0x").trim_start_matches("0X");

            // IPv4 (8个十六进制字符)
            if hex_str.len() == 8 {
                if let Ok(bytes) = hex::decode(hex_str) {
                    if bytes.len() == 4 {
                        return Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string();
                    }
                }
            }
            // IPv6 (32个十六进制字符)
            else if hex_str.len() == 32 {
                if let Ok(bytes) = hex::decode(hex_str) {
                    if bytes.len() == 16 {
                        let mut segments = [0u16; 8];
                        for i in 0..8 {
                            segments[i] = ((bytes[i*2] as u16) << 8) | (bytes[i*2+1] as u16);
                        }
                        return Ipv6Addr::new(
                            segments[0], segments[1], segments[2], segments[3],
                            segments[4], segments[5], segments[6], segments[7]
                        ).to_string();
                    }
                }
            }
            return "无效的十六进制IP格式".to_string();
        }
        "无效的IP地址格式".to_string()
    }

    // 端口转换函数
    pub fn port_to_network_order(&self, port_str: &str) -> String {
        if let Ok(port) = port_str.parse::<u16>() {
            let network_order = port.to_be();
            return format!("0x{:04X} ({})", network_order, network_order);
        }
        // 处理十六进制格式
        else if port_str.starts_with("0x") || port_str.starts_with("0X") {
            if let Ok(port) = u16::from_str_radix(port_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                let network_order = port.to_be();
                return format!("0x{:04X} ({})", network_order, network_order);
            }
        }
        "无效的端口格式".to_string()
    }

    pub fn port_to_host_order(&self, port_str: &str) -> String {
        // 处理十进制格式
        if let Ok(port) = port_str.parse::<u16>() {
            let host_order = u16::from_be(port);
            return format!("{} (0x{:04X})", host_order, host_order);
        }
        // 处理十六进制格式
        else if port_str.starts_with("0x") || port_str.starts_with("0X") {
            if let Ok(port) = u16::from_str_radix(port_str.trim_start_matches("0x").trim_start_matches("0X"), 16) {
                let host_order = u16::from_be(port);
                return format!("{} (0x{:04X})", host_order, host_order);
            }
        }
        "无效的端口格式".to_string()
    }

    // 整数转换函数
    pub fn int_to_network_order(&self, int_str: &str) -> String {
        // 尝试解析为 u32
        if let Ok(value) = int_str.parse::<u32>() {
            let network_order = value.to_be();
            return format!("0x{:08X} ({})", network_order, network_order);
        }
        // 尝试解析为 u64
        else if let Ok(value) = int_str.parse::<u64>() {
            let network_order = value.to_be();
            return format!("0x{:016X} ({})", network_order, network_order);
        }
        // 尝试解析十六进制 u32
        else if int_str.starts_with("0x") || int_str.starts_with("0X") {
            let hex_str = int_str.trim_start_matches("0x").trim_start_matches("0X");
            if hex_str.len() <= 8 {
                if let Ok(value) = u32::from_str_radix(hex_str, 16) {
                    let network_order = value.to_be();
                    return format!("0x{:08X} ({})", network_order, network_order);
                }
            } else {
                if let Ok(value) = u64::from_str_radix(hex_str, 16) {
                    let network_order = value.to_be();
                    return format!("0x{:016X} ({})", network_order, network_order);
                }
            }
        }
        "无效的整数格式".to_string()
    }

    pub fn int_to_host_order(&self, int_str: &str) -> String {
        // 尝试解析为 u32
        if let Ok(value) = int_str.parse::<u32>() {
            let host_order = u32::from_be(value);
            return format!("{} (0x{:08X})", host_order, host_order);
        }
        // 尝试解析为 u64
        else if let Ok(value) = int_str.parse::<u64>() {
            let host_order = u64::from_be(value);
            return format!("{} (0x{:016X})", host_order, host_order);
        }
        // 尝试解析十六进制 u32
        else if int_str.starts_with("0x") || int_str.starts_with("0X") {
            let hex_str = int_str.trim_start_matches("0x").trim_start_matches("0X");
            if hex_str.len() <= 8 {
                if let Ok(value) = u32::from_str_radix(hex_str, 16) {
                    let host_order = u32::from_be(value);
                    return format!("{} (0x{:08X})", host_order, host_order);
                }
            } else {
                if let Ok(value) = u64::from_str_radix(hex_str, 16) {
                    let host_order = u64::from_be(value);
                    return format!("{} (0x{:016X})", host_order, host_order);
                }
            }
        }
        "无效的整数格式".to_string()
    }
}