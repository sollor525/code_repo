//! PCAP文件写入器
//!
//! 用于将数据包写入PCAP文件

use std::fs::File;
use std::io::{self, Write};
use byteorder::{WriteBytesExt, LittleEndian};
use crate::types::Packet;

/// PCAP全局头部
#[derive(Debug, Clone)]
pub struct PcapGlobalHeader {
    /// 魔术数字 (0xa1b2c3d4)
    pub magic: u32,
    /// 主版本号 (通常为2)
    pub version_major: u16,
    /// 次版本号 (通常为4)
    pub version_minor: u16,
    /// 时区偏移 (GMT到本地时间的偏移，通常为0)
    pub thiszone: u32,
    /// 时间戳精度 (通常为0)
    pub sigfigs: u32,
    /// 数据包最大长度
    pub snaplen: u32,
    /// 链路层类型
    pub network: u32,
}

impl Default for PcapGlobalHeader {
    fn default() -> Self {
        Self {
            magic: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: 1, // DLT_EN10MB - Ethernet
        }
    }
}

/// PCAP数据包记录头部
#[derive(Debug, Clone)]
pub struct PcapPacketHeader {
    /// 时间戳（秒）
    pub ts_sec: u32,
    /// 时间戳（微秒）
    pub ts_usec: u32,
    /// 数据包实际长度
    pub caplen: u32,
    /// 数据包原始长度
    pub len: u32,
}

/// PCAP文件写入器
pub struct PcapWriter {
    file: File,
}

impl PcapWriter {
    /// 创建新的PCAP写入器
    pub fn new(file: File, network: u32) -> io::Result<Self> {
        let mut writer = Self { file };

        // 写入全局头部
        let header = PcapGlobalHeader {
            network,
            ..Default::default()
        };
        writer.write_global_header(&header)?;

        Ok(writer)
    }

    /// 写入全局头部
    fn write_global_header(&mut self, header: &PcapGlobalHeader) -> io::Result<()> {
        self.file.write_u32::<LittleEndian>(header.magic)?;
        self.file.write_u16::<LittleEndian>(header.version_major)?;
        self.file.write_u16::<LittleEndian>(header.version_minor)?;
        self.file.write_u32::<LittleEndian>(header.thiszone)?;
        self.file.write_u32::<LittleEndian>(header.sigfigs)?;
        self.file.write_u32::<LittleEndian>(header.snaplen)?;
        self.file.write_u32::<LittleEndian>(header.network)?;
        Ok(())
    }

    /// 写入数据包
    pub fn write_packet(&mut self, packet: &Packet) -> io::Result<()> {
        // 获取时间戳
        let timestamp = packet.header.timestamp();
        let ts_sec = timestamp.as_secs() as u32;
        let ts_usec = (timestamp.as_nanos() / 1000 % 1_000_000) as u32;

        // 写入数据包头部
        self.file.write_u32::<LittleEndian>(ts_sec)?;
        self.file.write_u32::<LittleEndian>(ts_usec)?;
        self.file.write_u32::<LittleEndian>(packet.header.caplen)?;
        self.file.write_u32::<LittleEndian>(packet.header.len)?;

        // 写入数据包数据
        self.file.write_all(&packet.data)?;

        Ok(())
    }

    /// 写入多个数据包
    pub fn write_packets(&mut self, packets: &[Packet]) -> io::Result<()> {
        for packet in packets {
            self.write_packet(packet)?;
        }
        Ok(())
    }

    /// 刷新缓冲区
    pub fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// 便利函数：创建PCAP写入器
pub fn create_pcap_writer(path: &str, network: u32) -> io::Result<PcapWriter> {
    let file = File::create(path)?;
    PcapWriter::new(file, network)
}