// TCP会话配置

use crate::core::{IpRange, PortRange, NetworkConnection, ApplicationFlowType, BuildError, session::TcpSession};
use crate::session::{SessionFactory, SessionBuilder};
use std::net::Ipv4Addr;

// TCP会话配置结构体
#[derive(Debug, Clone)]
pub struct TcpSessionConfig {
    pub src_ip_range: IpRange,
    pub dst_ip_range: IpRange,
    pub src_port_range: PortRange,
    pub dst_port_range: PortRange,
    pub session_count: u32,
    pub application_flow: ApplicationFlowType,
}

impl Default for TcpSessionConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpSessionConfig {
    pub fn new() -> Self {
        Self {
            src_ip_range: IpRange::new(
                Ipv4Addr::new(10, 10, 1, 100),
                Ipv4Addr::new(10, 10, 1, 100)
            ),
            dst_ip_range: IpRange::new(
                Ipv4Addr::new(192, 168, 1, 100),
                Ipv4Addr::new(192, 168, 1, 100)
            ),
            src_port_range: PortRange::new(30000, 40000),
            dst_port_range: PortRange::new(80, 80),
            session_count: 1,
            application_flow: ApplicationFlowType::TcpOnly,
        }
    }

    pub fn with_src_ip_range(mut self, range: IpRange) -> Self {
        self.src_ip_range = range;
        self
    }

    pub fn with_dst_ip_range(mut self, range: IpRange) -> Self {
        self.dst_ip_range = range;
        self
    }

    pub fn with_src_port_range(mut self, range: PortRange) -> Self {
        self.src_port_range = range;
        self
    }

    pub fn with_dst_port_range(mut self, range: PortRange) -> Self {
        self.dst_port_range = range;
        self
    }

    pub fn with_session_count(mut self, count: u32) -> Self {
        self.session_count = count;
        self
    }

    pub fn with_http(mut self, uris: Vec<String>, host: String) -> Self {
        self.application_flow = ApplicationFlowType::Http(
            crate::core::HttpFlow::new(uris, host)
        );
        self
    }

    pub fn with_application_flow(mut self, flow: ApplicationFlowType) -> Self {
        self.application_flow = flow;
        self
    }

    // 使用工厂模式生成会话
    pub fn generate_sessions(&self) -> Vec<TcpSession> {
        let factory = SessionFactory::new();
        let mut sessions = Vec::new();

        for _ in 0..self.session_count {
            let src_ip = self.src_ip_range.random_ip();
            let dst_ip = self.dst_ip_range.random_ip();
            let src_port = self.src_port_range.random_port();
            let dst_port = self.dst_port_range.random_port();

            let session = factory.create_session(
                src_ip, dst_ip, src_port, dst_port,
                self.application_flow.clone()
            );
            sessions.push(session);
        }

        sessions
    }

    // 使用自定义MAC地址生成会话
    pub fn generate_sessions_with_macs(&self, src_mac: [u8; 6], dst_mac: [u8; 6]) -> Vec<TcpSession> {
        let factory = SessionFactory::with_macs(src_mac, dst_mac);
        let mut sessions = Vec::new();

        for _ in 0..self.session_count {
            let src_ip = self.src_ip_range.random_ip();
            let dst_ip = self.dst_ip_range.random_ip();
            let src_port = self.src_port_range.random_port();
            let dst_port = self.dst_port_range.random_port();

            let session = factory.create_session(
                src_ip, dst_ip, src_port, dst_port,
                self.application_flow.clone()
            );
            sessions.push(session);
        }

        sessions
    }

    // 使用建造者模式创建单个会话
    pub fn build_session(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr,
                        src_port: u16, dst_port: u16) -> Result<TcpSession, BuildError> {
        let connection = NetworkConnection {
            src_mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            dst_mac: [0xe2, 0xc9, 0xfc, 0xf5, 0x9e, 0x3c],
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };

        SessionBuilder::new()
            .with_connection(connection)
            .with_application_flow(self.application_flow.clone())
            .build()
    }

    // 便利方法：创建纯TCP会话配置
    pub fn tcp_only() -> Self {
        Self::new()
    }

    // 便利方法：创建HTTP会话配置
    pub fn http_only(uris: Vec<String>, host: String) -> Self {
        Self::new().with_http(uris, host)
    }

    // 便利方法：创建随机会话配置
    pub fn random_network() -> Self {
        Self::new()
            .with_src_ip_range(IpRange::new(
                Ipv4Addr::new(0, 0, 0, 0),
                Ipv4Addr::new(255, 255, 255, 255)
            ))
            .with_dst_ip_range(IpRange::new(
                Ipv4Addr::new(0, 0, 0, 0),
                Ipv4Addr::new(255, 255, 255, 255)
            ))
            .with_src_port_range(PortRange::new(1, 65535))
            .with_dst_port_range(PortRange::new(1, 65535))
    }
}