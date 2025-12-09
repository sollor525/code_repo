//! PCAP文件读取器
//!
//! 提供PCAP文件的读取功能，支持字节序转换和迭代器模式

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use crate::types::packet::{Packet, PacketHeader};

/// PCAP文件错误类型
#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    #[error("IO错误: {0}")]
    Io(#[from] io::Error),
    #[error("无效的PCAP文件")]
    InvalidFile,
    #[error("不支持的PCAP版本: {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("不支持的链接层类型: {0}")]
    UnsupportedLinkType(u32),
    #[error("数据包截断")]
    TruncatedPacket,
    #[error("无效的字节序")]
    InvalidByteOrder,
}

/// PCAP全局头部
#[derive(Debug, Clone)]
pub struct PcapGlobalHeader {
    /// PCAP文件格式主版本号
    pub major_version: u16,
    /// PCAP文件格式次版本号
    pub minor_version: u16,
    /// 当前时间戳的修正值（GMT到本地时间的修正）
    pub thiszone: i32,
    /// 捕获数据包的最大长度（文件中每个数据包的最大长度）
    pub snaplen: u32,
    /// 链路层类型
    pub linktype: u32,
}

/// PCAP数据包头部
#[derive(Debug, Clone)]
pub struct PcapPacketHeader {
    /// 数据包捕获时间戳（秒）
    pub ts_sec: u32,
    /// 数据包捕获时间戳（微秒）
    pub ts_usec: u32,
    /// 数据包实际长度
    pub caplen: u32,
    /// 数据包原始长度
    pub len: u32,
}

/// PCAP文件读取器
pub struct PcapReader {
    /// 文件句柄
    file: File,
    /// 全局头部
    global_header: PcapGlobalHeader,
    /// 是否是大端字节序
    is_big_endian: bool,
    /// 当前位置
    current_position: u64,
}

impl PcapReader {
    /// 打开PCAP文件
    ///
    /// # 参数
    /// * `path` - PCAP文件路径
    ///
    /// # 返回值
    /// 返回PCAP读取器或错误
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, PcapError> {
        let mut file = File::open(path)?;
        let mut header_bytes = [0u8; 24];

        // 读取全局头部
        file.read_exact(&mut header_bytes)?;

        // 检查魔数，确定字节序
        let magic = u32::from_le_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]);
        let is_big_endian = match magic {
            0xA1B2C3D4 => false,  // 小端
            0xD4C3B2A1 => false,  // 小端（字节交换）
            0xA1B23C4D => true,   // 大端
            0x4D3CB2A1 => true,   // 大端（字节交换）
            _ => return Err(PcapError::InvalidFile),
        };

        // 读取版本号
        let (major_version, minor_version) = if is_big_endian {
            (
                u16::from_be_bytes([header_bytes[4], header_bytes[5]]),
                u16::from_be_bytes([header_bytes[6], header_bytes[7]])
            )
        } else {
            (
                u16::from_le_bytes([header_bytes[4], header_bytes[5]]),
                u16::from_le_bytes([header_bytes[6], header_bytes[7]])
            )
        };

        // 检查版本
        if major_version != 2 || minor_version != 4 {
            return Err(PcapError::UnsupportedVersion { major: major_version, minor: minor_version });
        }

        // 读取其他头部字段
        let thiszone = if is_big_endian {
            i32::from_be_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]])
        } else {
            i32::from_le_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]])
        };

        let snaplen = if is_big_endian {
            u32::from_be_bytes([header_bytes[12], header_bytes[13], header_bytes[14], header_bytes[15]])
        } else {
            u32::from_le_bytes([header_bytes[12], header_bytes[13], header_bytes[14], header_bytes[15]])
        };

        let linktype = if is_big_endian {
            u32::from_be_bytes([header_bytes[16], header_bytes[17], header_bytes[18], header_bytes[19]])
        } else {
            u32::from_le_bytes([header_bytes[16], header_bytes[17], header_bytes[18], header_bytes[19]])
        };

        // 检查链接层类型
        match linktype {
            1 | 6 | 10 | 101 | 65535 => {
                // 1: Ethernet (10Mb)
                // 6: Token Ring
                // 10: FDDI
                // 101: Raw IP
                // 65535: Linux cooked "any" or Raw IP variant
                // 这些都是支持的类型
            }
            _ => return Err(PcapError::UnsupportedLinkType(linktype)),
        }

        let global_header = PcapGlobalHeader {
            major_version,
            minor_version,
            thiszone,
            snaplen,
            linktype,
        };

        Ok(Self {
            file,
            global_header,
            is_big_endian,
            current_position: 24, // 全局头部之后
        })
    }

    /// 获取全局头部
    pub fn global_header(&self) -> &PcapGlobalHeader {
        &self.global_header
    }

    /// 读取下一个数据包
    ///
    /// # 返回值
    /// 返回数据包或None（文件结束）
    pub fn next_packet(&mut self) -> Result<Option<Packet>, PcapError> {
        // 读取数据包头部
        let mut header_bytes = [0u8; 16];
        match self.file.read_exact(&mut header_bytes) {
            Ok(_) => {},
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(PcapError::Io(e)),
        }

        // 解析数据包头部
        let (ts_sec, ts_usec) = if self.is_big_endian {
            (
                u32::from_be_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]),
                u32::from_be_bytes([header_bytes[4], header_bytes[5], header_bytes[6], header_bytes[7]])
            )
        } else {
            (
                u32::from_le_bytes([header_bytes[0], header_bytes[1], header_bytes[2], header_bytes[3]]),
                u32::from_le_bytes([header_bytes[4], header_bytes[5], header_bytes[6], header_bytes[7]])
            )
        };

        let (caplen, len) = if self.is_big_endian {
            (
                u32::from_be_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]]),
                u32::from_be_bytes([header_bytes[12], header_bytes[13], header_bytes[14], header_bytes[15]])
            )
        } else {
            (
                u32::from_le_bytes([header_bytes[8], header_bytes[9], header_bytes[10], header_bytes[11]]),
                u32::from_le_bytes([header_bytes[12], header_bytes[13], header_bytes[14], header_bytes[15]])
            )
        };

        // 读取数据包数据
        let mut packet_data = vec![0u8; caplen as usize];
        self.file.read_exact(&mut packet_data)?;

        // 创建数据包
        let header = PacketHeader::new(ts_sec, ts_usec, caplen, len);
        let packet = Packet::new(header, packet_data);

        // 更新当前位置
        self.current_position += 16 + caplen as u64;

        Ok(Some(packet))
    }

    /// 跳转到指定位置（字节）
    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64, PcapError> {
        let new_pos = self.file.seek(pos)?;
        self.current_position = new_pos;
        Ok(new_pos)
    }

    /// 获取当前文件位置
    pub fn position(&self) -> u64 {
        self.current_position
    }

    /// 重置到文件开头（跳过全局头部）
    pub fn reset(&mut self) -> Result<(), PcapError> {
        self.seek(SeekFrom::Start(24))?;
        Ok(())
    }
}

impl Iterator for PcapReader {
    type Item = Result<Packet, PcapError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_packet() {
            Ok(Some(packet)) => Some(Ok(packet)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_pcap_reader_invalid_magic() {
        // 创建一个无效的临时文件
        let mut temp_file = NamedTempFile::new().unwrap();
        // 写入无效的魔数 + 一些填充字节以构成最小 PCAP 头部
        temp_file.write_all(b"\x00\x00\x00\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00").unwrap();

        let result = PcapReader::open(temp_file.path());
        assert!(matches!(result, Err(PcapError::InvalidFile)));
    }
}