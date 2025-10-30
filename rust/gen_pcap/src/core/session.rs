// 会话层抽象

use crate::core::network::NetworkConnection;

// 前向声明TcpSession
#[derive(Debug, Clone)]
pub struct TcpSession {
    pub connection: NetworkConnection,
    pub isn: u32,
}

impl TcpSession {
    pub fn new(connection: NetworkConnection, isn: u32) -> Self {
        Self { connection, isn }
    }
}

// 应用层流量抽象
pub trait ApplicationFlow {
    fn generate_packets(&self, session: &TcpSession) -> Vec<Vec<u8>>;
    fn name(&self) -> &'static str;
}

// TCP会话基础结构 - 移动到lib.rs作为主要导出
// 这样可以避免循环依赖问题

// 为了支持克隆，我们需要一个包装器
#[derive(Debug, Clone)]
pub enum ApplicationFlowType {
    Http(HttpFlow),
    TcpOnly,
}

impl ApplicationFlow for ApplicationFlowType {
    fn generate_packets(&self, session: &TcpSession) -> Vec<Vec<u8>> {
        match self {
            ApplicationFlowType::Http(flow) => flow.generate_packets(session),
            ApplicationFlowType::TcpOnly => TcpOnlyFlow.generate_packets(session),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ApplicationFlowType::Http(_) => "HTTP",
            ApplicationFlowType::TcpOnly => "TCP_ONLY",
        }
    }
}

// HTTP流量实现
#[derive(Debug, Clone)]
pub struct HttpFlow {
    pub uris: Vec<String>,
    pub host: String,
}

impl HttpFlow {
    pub fn new(uris: Vec<String>, host: String) -> Self {
        Self { uris, host }
    }
}

impl ApplicationFlow for HttpFlow {
    fn generate_packets(&self, session: &TcpSession) -> Vec<Vec<u8>> {
        // 使用HTTP模块中的实现生成流量
        crate::http::flow::HttpFlowImplementation::generate_packets(&self.uris, &self.host, session)
    }

    fn name(&self) -> &'static str {
        "HTTP"
    }
}

// 纯TCP流量实现（无应用层）
#[derive(Debug, Clone)]
pub struct TcpOnlyFlow;

impl ApplicationFlow for TcpOnlyFlow {
    fn generate_packets(&self, session: &TcpSession) -> Vec<Vec<u8>> {
        // 返回TCP三次握手包
        use crate::tcp::build_tcp_handshake_packets;

        let (handshake_packets, _) = build_tcp_handshake_packets(
            session.connection.src_mac,
            session.connection.dst_mac,
            session.connection.src_ip,
            session.connection.dst_ip,
            session.connection.src_port,
            session.connection.dst_port,
            session.isn
        );

        handshake_packets
    }

    fn name(&self) -> &'static str {
        "TCP_ONLY"
    }
}