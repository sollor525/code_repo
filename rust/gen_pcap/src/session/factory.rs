// 会话工厂

use crate::core::{NetworkConnection, ApplicationFlowType, session::TcpSession};
use rand::Rng;

// 会话工厂
#[derive(Debug, Clone)]
pub struct SessionFactory {
    default_src_mac: [u8; 6],
    default_dst_mac: [u8; 6],
}

impl SessionFactory {
    pub fn new() -> Self {
        Self {
            default_src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            default_dst_mac: [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c],
        }
    }

    pub fn with_macs(src_mac: [u8; 6], dst_mac: [u8; 6]) -> Self {
        Self { default_src_mac: src_mac, default_dst_mac: dst_mac }
    }

    pub fn create_session(&self, src_ip: std::net::Ipv4Addr, dst_ip: std::net::Ipv4Addr,
                         src_port: u16, dst_port: u16,
                         _application_flow: ApplicationFlowType) -> TcpSession {
        let connection = NetworkConnection {
            src_mac: self.default_src_mac,
            dst_mac: self.default_dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };

        let mut rng = rand::thread_rng();
        let isn = rng.gen_range(1000000..2000000);

        TcpSession { connection, isn }
    }

    pub fn create_session_with_isn(&self, src_ip: std::net::Ipv4Addr, dst_ip: std::net::Ipv4Addr,
                                 src_port: u16, dst_port: u16,
                                 _application_flow: ApplicationFlowType,
                                 isn: u32) -> TcpSession {
        let connection = NetworkConnection {
            src_mac: self.default_src_mac,
            dst_mac: self.default_dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };

        TcpSession { connection, isn }
    }
}

impl Default for SessionFactory {
    fn default() -> Self {
        Self::new()
    }
}