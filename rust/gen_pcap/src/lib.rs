//! gen_pcap - PCAP文件生成工具库
//!
//! 提供TCP和HTTP流量的PCAP文件生成功能


// 导出核心模块
pub mod core;
pub mod tcp;
pub mod http;
pub mod session;
pub mod template;
pub mod license;
pub mod vlan;

// 重新导出主要公共接口
pub use core::{
    NetworkConnection, IpRange, PortRange, BuildError, PcapError,
    session::{TcpSession, ApplicationFlow, ApplicationFlowType}
};
pub use session::{
    SessionBuilder, SessionFactory, TcpSessionConfig
};

// 便利函数导出
pub use tcp::build_tcp_handshake_packets;

// HTTP相关类型的导出
pub use http::{
    request::{HttpRequest, HttpMethod, HttpVersion},
    response::{HttpResponse, HttpStatusCode}
};

// 模板相关类型的导出
pub use template::{
    YamlTemplate, TemplateEngine, TemplateConfig,
    TemplateError, TemplateMetadata, NetworkConfig, SessionTemplate,
    AddressConfig, SessionType, ApplicationConfig, HttpRequestConfig,
    HttpResponseConfig, DefaultSettings
};

// 许可证相关类型导出
pub use license::{LicenseManager, ProgramConfig, UsageCounter};

// VLAN相关类型导出
pub use vlan::{VlanTag, VlanConfig, parse_mac_address, build_vlan_ethernet_header};

// TcpSession实现 - 统一使用一个主要方法
impl TcpSession {
    /// 生成数据包
    pub fn generate_packets(&self, flow: &dyn ApplicationFlow) -> Vec<Vec<u8>> {
        flow.generate_packets(self)
    }
}