use std::net::IpAddr;
use std::process;
use std::env;
use crate::common::session::{FiveTuple, Protocol};

pub fn get_process_info() -> (u32, String, String) {
    let pid = process::id();
    let exe_path = env::current_exe()
        .unwrap_or_else(|_| "unknown".into())
        .to_string_lossy()
        .to_string();
    let process_name = exe_path
        .split('/')
        .last()
        .unwrap_or("unknown")
        .to_string();

    let command_line = std::env::args().collect::<Vec<_>>().join(" ");

    (pid, process_name, command_line)
}

pub fn parse_ip(ip_str: &str) -> Result<IpAddr, std::net::AddrParseError> {
    ip_str.parse::<IpAddr>()
}

pub fn parse_five_tuple(
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
    protocol: &str,
) -> Result<FiveTuple, Box<dyn std::error::Error>> {
    let protocol = match protocol.to_uppercase().as_str() {
        "TCP" => Protocol::TCP,
        "UDP" => Protocol::UDP,
        _ => return Err("Invalid protocol".into()),
    };

    Ok(FiveTuple {
        src_ip: parse_ip(src_ip)?,
        src_port,
        dst_ip: parse_ip(dst_ip)?,
        dst_port,
        protocol,
    })
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex_str)
}

pub fn validate_client_random(client_random: &[u8]) -> bool {
    client_random.len() == 32
}

pub fn validate_master_secret(master_secret: &[u8]) -> bool {
    master_secret.len() == 48
}

pub fn get_local_ip() -> Option<IpAddr> {
    local_ip::get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_five_tuple() {
        let result = parse_five_tuple("192.168.1.1", 12345, "192.168.1.2", 443, "TCP");
        assert!(result.is_ok());

        let five_tuple = result.unwrap();
        assert_eq!(five_tuple.src_port, 12345);
        assert_eq!(five_tuple.dst_port, 443);
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "12345678");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex_str = "12345678";
        let bytes = hex_to_bytes(hex_str).unwrap();
        assert_eq!(bytes, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_validate_client_random() {
        let valid = [0u8; 32];
        let invalid = [0u8; 16];

        assert!(validate_client_random(&valid));
        assert!(!validate_client_random(&invalid));
    }

    #[test]
    fn test_validate_master_secret() {
        let valid = [0u8; 48];
        let invalid = [0u8; 32];

        assert!(validate_master_secret(&valid));
        assert!(!validate_master_secret(&invalid));
    }
}