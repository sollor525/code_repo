//! genpcap —— TCP/HTTP/VLAN 流量的 PCAP 报文生成核心
//!
//! 自 `rust/gen_pcap` 移植，仅保留**纯计算**的数据包生成逻辑：
//! 去除文件 IO、许可证（license）与 YAML 模板（template），也不再依赖
//! 原项目用于落盘的 `pcap`（libpcap）crate —— 字节由调用方在内存中序列化为
//! PCAP（common_tools 使用 `pcap_file`）。

// 生成所需的核心模块（与 gen_pcap 同构，内部 `crate::` 路径保持有效）
pub mod core;
pub mod tcp;
pub mod http;
pub mod session;
pub mod vlan;

// 报文序列生成扩展（TCP 模式 / 自定义 HTTP / ICMP / UDP / FTP / SSH / MySQL）
pub mod conversation;
pub mod l4;
pub mod flows;

// 重新导出主要公共接口
pub use core::{
    NetworkConnection, IpRange, IpVersion, PortRange, BuildError, PcapError,
    session::{
        TcpSession, ApplicationFlow, ApplicationFlowType, GenOptions,
        TcpMode, HttpConfig, IcmpConfig, UdpConfig, FtpMode,
    },
};
pub use session::{SessionBuilder, SessionFactory, TcpSessionConfig};

// 便利函数导出
pub use tcp::build_tcp_handshake_packets;

// HTTP 相关类型导出
pub use http::{
    request::{HttpRequest, HttpMethod, HttpVersion},
    response::{HttpResponse, HttpStatusCode},
};

// VLAN 相关类型导出
pub use vlan::{VlanTag, VlanConfig, parse_mac_address, build_vlan_ethernet_header};

impl TcpSession {
    /// 生成数据包
    pub fn generate_packets(&self, flow: &dyn ApplicationFlow, opts: &GenOptions) -> Vec<Vec<u8>> {
        flow.generate_packets(self, opts)
    }
}
