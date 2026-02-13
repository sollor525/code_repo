//! 网络工具函数

use std::net::{Ipv4Addr, Ipv6Addr};

/// 网络工具函数
pub struct NetworkUtils;

impl NetworkUtils {
    /// 检查 IP 是否在网段内
    pub fn ip_in_network(ip: Ipv4Addr, network: Ipv4Addr, mask: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let network_u32 = u32::from(network);
        let mask_u32 = u32::from(mask);

        (ip_u32 & mask_u32) == (network_u32 & mask_u32)
    }

    /// 计算 IPv4 子网掩码
    pub fn ipv4_mask(prefix_len: u8) -> Ipv4Addr {
        if prefix_len > 32 {
            return Ipv4Addr::new(255, 255, 255, 255);
        }

        let mask = if prefix_len == 0 {
            0u32
        } else {
            0xFFFFFFFFu32 << (32 - prefix_len)
        };

        let octets = mask.to_be_bytes();
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
    }

    /// 格式化 MAC 地址
    pub fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }
}