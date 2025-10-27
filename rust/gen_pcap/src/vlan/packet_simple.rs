//! 简化的VLAN数据包构建功能
//!
//! 专注于基本VLAN支持，使用现有的数据包构建逻辑



/// VLAN标签配置
#[derive(Debug, Clone)]
pub struct VlanTag {
    /// VLAN ID (1-4094)
    pub vlan_id: u16,
    /// 优先级 (0-7)
    pub priority: u8,
    /// DEI位 (Drop Eligible Indicator)
    pub dei: bool,
}

impl VlanTag {
    pub fn new(vlan_id: u16, priority: u8, dei: bool) -> Self {
        Self {
            vlan_id,
            priority,
            dei,
        }
    }

    /// 创建VLAN TCI (Tag Control Information)
    pub fn to_tci(&self) -> u16 {
        let mut tci = 0u16;

        // PCP: Priority Code Point (bits 13-15)
        tci |= ((self.priority as u16) & 0x07) << 13;

        // DEI: Drop Eligible Indicator (bit 12)
        if self.dei {
            tci |= 1 << 12;
        }

        // VLAN ID (bits 0-11)
        tci |= self.vlan_id & 0x0FFF;

        tci
    }
}

/// VLAN配置
#[derive(Debug, Clone)]
pub struct VlanConfig {
    /// 外层VLAN标签
    pub outer_tag: Option<VlanTag>,
    /// 内层VLAN标签 (用于QinQ)
    pub inner_tag: Option<VlanTag>,
    /// 是否为QinQ (双层VLAN)
    pub is_qinq: bool,
}

impl VlanConfig {
    pub fn new() -> Self {
        Self {
            outer_tag: None,
            inner_tag: None,
            is_qinq: false,
        }
    }

    /// 创建单层VLAN配置
    pub fn single_layer(vlan_id: u16, priority: u8, dei: bool) -> Self {
        Self {
            outer_tag: Some(VlanTag::new(vlan_id, priority, dei)),
            inner_tag: None,
            is_qinq: false,
        }
    }

    /// 创建双层VLAN (QinQ) 配置
    pub fn double_layer(outer_vlan_id: u16, inner_vlan_id: u16,
                        outer_priority: u8, inner_priority: u8) -> Self {
        Self {
            outer_tag: Some(VlanTag::new(outer_vlan_id, outer_priority, false)),
            inner_tag: Some(VlanTag::new(inner_vlan_id, inner_priority, false)),
            is_qinq: true,
        }
    }

    /// 添加VLAN标签到现有数据包
    pub fn add_vlan_tags(&self, packet: Vec<u8>) -> Vec<u8> {
        if !self.is_qinq && self.outer_tag.is_none() {
            return packet; // 没有VLAN配置，返回原数据包
        }

        let original_len = packet.len();

        if self.is_qinq {
            // QinQ: 添加两个VLAN标签 (8字节)
            let mut new_packet = Vec::with_capacity(original_len + 8);

            // 复制以太网头 (前14字节)
            if original_len >= 14 {
                new_packet.extend_from_slice(&packet[..14]);
            } else {
                new_packet.extend_from_slice(&packet);
                return new_packet;
            }

            // 添加外层VLAN标签
            if let Some(outer_tag) = &self.outer_tag {
                new_packet.extend_from_slice(&outer_tag.to_tci().to_be_bytes());
                new_packet.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN EtherType
            }

            // 添加内层VLAN标签
            if let Some(inner_tag) = &self.inner_tag {
                new_packet.extend_from_slice(&inner_tag.to_tci().to_be_bytes());
                new_packet.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType
            }

            // 复制剩余数据 (去掉原以太网头)
            if original_len > 14 {
                new_packet.extend_from_slice(&packet[14..]);
            }

            new_packet
        } else {
            // 单层VLAN: 添加一个VLAN标签 (4字节)
            let mut new_packet = Vec::with_capacity(original_len + 4);

            // 复制以太网头 (前14字节)
            if original_len >= 14 {
                new_packet.extend_from_slice(&packet[..14]);
            } else {
                new_packet.extend_from_slice(&packet);
                return new_packet;
            }

            // 添加VLAN标签
            if let Some(vlan_tag) = &self.outer_tag {
                new_packet.extend_from_slice(&vlan_tag.to_tci().to_be_bytes());
                new_packet.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType
            }

            // 复制剩余数据 (去掉原以太网头)
            if original_len > 14 {
                new_packet.extend_from_slice(&packet[14..]);
            }

            new_packet
        }
    }
}

/// 解析MAC地址字符串
pub fn parse_mac_address(mac_str: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return Err("MAC地址格式错误，期望格式: XX:XX:XX:XX:XX:XX".to_string());
    }

    let mut mac_bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac_bytes[i] = u8::from_str_radix(part, 16)
            .map_err(|_| format!("无效的MAC地址段: {}", part))?;
    }

    Ok(mac_bytes)
}

/// 构建VLAN以太网帧头
pub fn build_vlan_ethernet_header(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    vlan_config: &VlanConfig,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(22); // 最大: 14 + 4 + 4

    // 以太网头 (14字节)
    header.extend_from_slice(&dst_mac);
    header.extend_from_slice(&src_mac);

    if vlan_config.is_qinq {
        // QinQ配置
        header.extend_from_slice(&0x88A8u16.to_be_bytes()); // QinQ EtherType

        // 外层VLAN标签
        if let Some(outer_tag) = &vlan_config.outer_tag {
            header.extend_from_slice(&outer_tag.to_tci().to_be_bytes());
        }

        // 内层VLAN标签
        header.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN EtherType
        if let Some(inner_tag) = &vlan_config.inner_tag {
            header.extend_from_slice(&inner_tag.to_tci().to_be_bytes());
        }

        header.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType
    } else if let Some(vlan_tag) = &vlan_config.outer_tag {
        // 单层VLAN配置
        header.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN EtherType
        header.extend_from_slice(&vlan_tag.to_tci().to_be_bytes());
        header.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType
    } else {
        // 无VLAN配置
        header.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType
    }

    header
}