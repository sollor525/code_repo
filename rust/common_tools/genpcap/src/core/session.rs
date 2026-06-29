// 会话层抽象 + 应用流量类型

use crate::core::network::NetworkConnection;

// TcpSession：一条会话的寻址信息 + 初始序列号
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

// ----------------------------- 流量配置 -----------------------------

/// 纯 TCP 模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMode {
    /// 仅 SYN（半连接扫描风格）
    SynOnly,
    /// 三次握手
    Handshake,
    /// 三次握手后四次挥手关闭
    HandshakeClose,
    /// 三次握手后 RST 复位
    HandshakeReset,
}

/// HTTP：默认按 uris/host 生成 GET，或指定自定义请求/响应内容
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub uris: Vec<String>,
    pub host: String,
    pub request_content: Option<String>,
    pub response_content: Option<String>,
}

/// ICMP echo（请求/应答对数）
#[derive(Debug, Clone)]
pub struct IcmpConfig {
    pub count: u32,
}

/// UDP（载荷 + 是否生成应答）
#[derive(Debug, Clone)]
pub struct UdpConfig {
    pub payload: Vec<u8>,
    pub with_response: bool,
}

/// FTP 模式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpMode {
    Active,
    Passive,
}

// 应用流量类型（克隆友好，便于按会话复用配置）
#[derive(Debug, Clone)]
pub enum ApplicationFlowType {
    Tcp(TcpMode),
    Http(HttpConfig),
    Icmp(IcmpConfig),
    Udp(UdpConfig),
    Ftp(FtpMode),
    Ssh,
    Mysql,
}

impl ApplicationFlow for ApplicationFlowType {
    fn generate_packets(&self, session: &TcpSession) -> Vec<Vec<u8>> {
        match self {
            ApplicationFlowType::Tcp(mode) => crate::flows::tcp_mode(session, *mode),
            ApplicationFlowType::Http(cfg) => crate::flows::http(session, cfg),
            ApplicationFlowType::Icmp(cfg) => crate::flows::icmp(session, cfg),
            ApplicationFlowType::Udp(cfg) => crate::flows::udp(session, cfg),
            ApplicationFlowType::Ftp(mode) => crate::flows::ftp(session, *mode),
            ApplicationFlowType::Ssh => crate::flows::ssh(session),
            ApplicationFlowType::Mysql => crate::flows::mysql(session),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            ApplicationFlowType::Tcp(_) => "TCP",
            ApplicationFlowType::Http(_) => "HTTP",
            ApplicationFlowType::Icmp(_) => "ICMP",
            ApplicationFlowType::Udp(_) => "UDP",
            ApplicationFlowType::Ftp(_) => "FTP",
            ApplicationFlowType::Ssh => "SSH",
            ApplicationFlowType::Mysql => "MySQL",
        }
    }
}
