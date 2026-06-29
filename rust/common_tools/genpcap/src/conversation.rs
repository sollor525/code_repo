//! 一条 TCP 会话的报文构造器。
//!
//! 跟踪客户端 / 服务器各自的 seq，按需在发送时计算 ack（始终确认对端已发送的全部
//! 字节），从而产出 seq/ack 自洽、Wireshark 可正常重组的 TCP 流。底层经
//! `build_tcp_packet_with_data` 按 IP 版本（IPv4 / IPv6）自动分发。

use crate::tcp::packet::{build_tcp_packet_with_data, TcpPacketWithDataParams};
use pnet_packet::tcp::TcpFlags;
use std::net::IpAddr;

pub struct TcpConversation {
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    /// 客户端下一个要使用的序列号
    cseq: u32,
    /// 服务器下一个要使用的序列号
    sseq: u32,
    /// 最大 TCP 段大小（payload 上限）；0 = 不分段
    mss: usize,
    pub packets: Vec<Vec<u8>>,
}

impl TcpConversation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        client_isn: u32,
        server_isn: u32,
    ) -> Self {
        Self {
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            cseq: client_isn,
            sseq: server_isn,
            mss: 0,
            packets: Vec::new(),
        }
    }

    /// 设置最大 TCP 段大小；超过该值的 client_data/server_data 将拆成多个 TCP 段。
    pub fn set_mss(&mut self, mss: usize) {
        self.mss = mss;
    }

    /// 低层：按方向发送一个报文。`ack` 为显式确认号（无 ACK 标志时通常传 0）。
    fn push(&mut self, from_client: bool, flags: u16, ack: u32, data: &[u8]) {
        let params = if from_client {
            TcpPacketWithDataParams::new(
                self.src_mac, self.dst_mac, self.src_ip, self.dst_ip,
                self.src_port, self.dst_port, self.cseq, ack, flags, data.to_vec(),
            )
        } else {
            TcpPacketWithDataParams::new(
                self.dst_mac, self.src_mac, self.dst_ip, self.src_ip,
                self.dst_port, self.src_port, self.sseq, ack, flags, data.to_vec(),
            )
        };
        self.packets.push(build_tcp_packet_with_data(params));
    }

    /// 仅发送 SYN（半连接 / 仅 SYN 模式）
    pub fn syn_only(&mut self) {
        self.push(true, TcpFlags::SYN, 0, &[]);
        self.cseq = self.cseq.wrapping_add(1);
    }

    /// 三次握手：SYN → SYN/ACK → ACK
    pub fn handshake(&mut self) {
        self.push(true, TcpFlags::SYN, 0, &[]);
        self.cseq = self.cseq.wrapping_add(1);

        self.push(false, TcpFlags::SYN | TcpFlags::ACK, self.cseq, &[]);
        self.sseq = self.sseq.wrapping_add(1);

        self.push(true, TcpFlags::ACK, self.sseq, &[]);
    }

    /// 按 MSS 切分数据；mss==0 或数据较小时返回单块。
    fn segments<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        if self.mss == 0 || data.len() <= self.mss {
            vec![data]
        } else {
            data.chunks(self.mss).collect()
        }
    }

    /// 客户端发送数据（按 MSS 分段，PSH 置于最后一段），随后服务器回一个 ACK
    pub fn client_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let segs = self.segments(data);
        let last = segs.len() - 1;
        for (i, seg) in segs.iter().enumerate() {
            let flags = if i == last { TcpFlags::PSH | TcpFlags::ACK } else { TcpFlags::ACK };
            self.push(true, flags, self.sseq, seg);
            self.cseq = self.cseq.wrapping_add(seg.len() as u32);
        }
        self.push(false, TcpFlags::ACK, self.cseq, &[]);
    }

    /// 服务器发送数据（按 MSS 分段，PSH 置于最后一段），随后客户端回一个 ACK
    pub fn server_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let segs = self.segments(data);
        let last = segs.len() - 1;
        for (i, seg) in segs.iter().enumerate() {
            let flags = if i == last { TcpFlags::PSH | TcpFlags::ACK } else { TcpFlags::ACK };
            self.push(false, flags, self.cseq, seg);
            self.sseq = self.sseq.wrapping_add(seg.len() as u32);
        }
        self.push(true, TcpFlags::ACK, self.sseq, &[]);
    }

    /// 四次挥手（客户端发起）：FIN/ACK → ACK → FIN/ACK → ACK
    pub fn close_graceful(&mut self) {
        self.push(true, TcpFlags::FIN | TcpFlags::ACK, self.sseq, &[]);
        self.cseq = self.cseq.wrapping_add(1);

        self.push(false, TcpFlags::ACK, self.cseq, &[]);

        self.push(false, TcpFlags::FIN | TcpFlags::ACK, self.cseq, &[]);
        self.sseq = self.sseq.wrapping_add(1);

        self.push(true, TcpFlags::ACK, self.sseq, &[]);
    }

    /// 握手后复位（客户端 RST/ACK）
    pub fn reset(&mut self) {
        self.push(true, TcpFlags::RST | TcpFlags::ACK, self.sseq, &[]);
    }

    /// 取走累积的报文
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.packets)
    }

    pub fn into_packets(self) -> Vec<Vec<u8>> {
        self.packets
    }
}
