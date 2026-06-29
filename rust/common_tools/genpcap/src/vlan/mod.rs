//! VLAN数据包处理模块
//!
//! 支持单层VLAN和双层VLAN (QinQ) 数据包的生成

pub mod packet_simple;

// 重新导出公共接口
pub use packet_simple::{
    VlanTag, VlanConfig, parse_mac_address,
    build_vlan_ethernet_header
};