use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSession {
    pub session_id: String,
    pub client_random: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub five_tuple: FiveTuple,
    pub timestamp: u64,
    pub process_info: ProcessInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub command_line: String,
}

impl TlsSession {
    pub fn new(
        client_random: Vec<u8>,
        master_secret: Vec<u8>,
        five_tuple: FiveTuple,
        process_info: ProcessInfo,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session_id = format!(
            "{}:{}-{}:{}-{}",
            five_tuple.src_ip,
            five_tuple.src_port,
            five_tuple.dst_ip,
            five_tuple.dst_port,
            timestamp
        );

        Self {
            session_id,
            client_random,
            master_secret,
            five_tuple,
            timestamp,
            process_info,
        }
    }

    pub fn matches_filter(&self, filter: &FiveTuple) -> bool {
        (filter.src_ip.is_unspecified() || filter.src_ip == self.five_tuple.src_ip) &&
        (filter.dst_ip.is_unspecified() || filter.dst_ip == self.five_tuple.dst_ip) &&
        (filter.src_port == 0 || filter.src_port == self.five_tuple.src_port) &&
        (filter.dst_port == 0 || filter.dst_port == self.five_tuple.dst_port) &&
        std::mem::discriminant(&filter.protocol) == std::mem::discriminant(&self.five_tuple.protocol)
    }
}

impl FiveTuple {
    pub fn from_socket(local: SocketAddr, remote: SocketAddr, protocol: Protocol) -> Self {
        Self {
            src_ip: local.ip(),
            src_port: local.port(),
            dst_ip: remote.ip(),
            dst_port: remote.port(),
            protocol,
        }
    }

    pub fn wildcard() -> Self {
        Self {
            src_ip: "0.0.0.0".parse().unwrap(),
            src_port: 0,
            dst_ip: "0.0.0.0".parse().unwrap(),
            dst_port: 0,
            protocol: Protocol::TCP,
        }
    }
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::TCP
    }
}