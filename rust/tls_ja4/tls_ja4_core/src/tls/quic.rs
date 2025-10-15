//! QUIC协议检测模块

/// 检查是否为QUIC数据包
pub fn is_quic_packet(packet: &[u8]) -> bool {
    // 首先进行基本的QUIC检测
    if !is_quic_packet_basic(packet) {
        return false;
    }

    // 额外的验证：检查包的特征
    // 1. 检查包长度是否在合理范围内
    if packet.len() < 50 || packet.len() > 1500 {
        return false;
    }

    // 2. 检查第一个字节是否合理
    let first_byte = packet[0];

    // 对于Short Header，检查Packet Number Length是否合理
    if (first_byte & 0x80) == 0 {
        let pn_length = (first_byte & 0x03) + 1;
        if !(1..=4).contains(&pn_length) {
            return false;
        }

        // 检查Packet Number字段
        if packet.len() > pn_length as usize {
            let pn_bytes = &packet[1..1 + pn_length as usize];
            let pn_value = pn_bytes.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);

            // Packet Number不能为0或全为1
            if pn_value == 0 || pn_value == (1u32 << (pn_length * 8)) - 1 {
                return false;
            }
        }
    }

    // 3. 检查包的内容是否合理
    // 对于QUIC包，应该有一些加密的数据
    if packet.len() > 20 {
        // 检查是否有足够的随机性（避免检测到其他协议）
        let mut entropy = 0u32;
        for &byte in &packet[10..std::cmp::min(50, packet.len())] {
            entropy ^= byte as u32;
        }

        // 如果熵值太低，可能不是QUIC包
        if entropy < 10 {
            return false;
        }
    }

    true
}

/// 基本的QUIC包检测
/// 专注于检测QUIC Initial包（packet_type == 0），因为只有Initial包包含TLS ClientHello
fn is_quic_packet_basic(packet: &[u8]) -> bool {
    if packet.len() < 5 {
        return false;
    }

    let first_byte = packet[0];

    // QUIC Long Header检测：第一个字节的最高位为1
    if (first_byte & 0x80) != 0 {
        // 检查Packet Type (第1个字节的5-6位)
        let packet_type = (first_byte & 0x30) >> 4;

        // 检查版本字段 (字节1-4)
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

        // 检查是否为有效的QUIC版本 (QUIC版本1 = 0x00000001)
        if version != 0x00000001 {
            return false;
        }

        // 要求包长度至少100字节（QUIC包通常比较大）
        if packet.len() < 100 {
            return false;
        }

        // 只接受Initial包（packet_type == 0），因为只有Initial包包含TLS ClientHello
        match packet_type {
            0x0 => true, // Initial - 包含TLS ClientHello
            _ => false,   // 其他包类型不包含ClientHello，不需要检测
        }
    } else {
        // QUIC Short Header不包含TLS ClientHello，不需要检测
        false
    }
}