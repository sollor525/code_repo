//! PCAP流分析器库
//!
//! 提供PCAP文件读取、解析和流分析功能

pub mod pcap;
pub mod types;
pub mod stream;
pub mod output;
pub mod protocol;
pub mod rayon_parallel;
pub mod time_limit;

// 重新导出主要类型
pub use pcap::{PcapReader, PacketParser, PcapError};
pub use types::packet::{Packet, PacketHeader, Protocol, TcpFlags};
pub use types::flow::{FlowKey, FlowStats};
pub use types::stream::{TcpStream, TcpState};