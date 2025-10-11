//! Client Hello解析功能

use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsVersion};

/// Client Hello解析结果类型别名
pub type ClientHelloData = (TlsVersion, Vec<u16>, Vec<u16>, Vec<u16>, Vec<u8>, Vec<u16>);

/// 解析Client Hello并提取指纹数据
pub fn parse_client_hello_with_tls_parser(payload: &[u8]) -> Option<ClientHelloData> {
    match parse_tls_plaintext(payload) {
        Ok((_, tls_plaintext)) => {
            // 简化实现，直接返回基本数据
            if let Some(TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello))) = tls_plaintext.msg.first() {
                let version = client_hello.version;

                // 提取密码套件
                let ciphers: Vec<u16> = client_hello.ciphers.iter()
                    .map(|&c| u16::from(c))
                    .collect();

                // 提取扩展
                let (extensions, elliptic_curves, ec_point_formats, signature_algorithms) =
                    if let Some(extensions_data) = &client_hello.ext {
                        parse_tls_extensions_correctly(extensions_data)
                    } else {
                        (Vec::new(), Vec::new(), Vec::new(), Vec::new())
                    };

                Some((version, ciphers, extensions, elliptic_curves, ec_point_formats, signature_algorithms))
            } else {
                None
            }
        },
        Err(_) => None
    }
}

/// 正确解析TLS扩展
fn parse_tls_extensions_correctly(extensions_data: &[u8]) -> (Vec<u16>, Vec<u16>, Vec<u8>, Vec<u16>) {
    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut signature_algorithms = Vec::new();
    
    // 使用tls-parser解析扩展
    match tls_parser::parse_tls_extensions(extensions_data) {
        Ok((_, parsed_extensions)) => {
            for extension in parsed_extensions {
                match extension {
                    tls_parser::TlsExtension::SNI(_) => {
                        extensions.push(0); // SNI extension
                    }
                    tls_parser::TlsExtension::EllipticCurves(curves) => {
                        extensions.push(10); // supported_groups
                        for curve in curves {
                            elliptic_curves.push(curve.0);
                        }
                    }
                    tls_parser::TlsExtension::EcPointFormats(formats) => {
                        extensions.push(11); // ec_point_formats
                        for &format in formats {
                            ec_point_formats.push(format);
                        }
                    }
                    tls_parser::TlsExtension::SignatureAlgorithms(algs) => {
                        extensions.push(13); // signature_algorithms
                        for alg in algs {
                            signature_algorithms.push(alg);
                        }
                    }
                    tls_parser::TlsExtension::ALPN(_) => {
                        extensions.push(16); // ALPN
                    }
                    tls_parser::TlsExtension::SupportedVersions(_) => {
                        extensions.push(43); // supported_versions
                    }
                    tls_parser::TlsExtension::MaxFragmentLength(_) => {
                        extensions.push(1); // max_fragment_length
                    }
                    tls_parser::TlsExtension::StatusRequest(_) => {
                        extensions.push(5); // status_request
                    }
                    tls_parser::TlsExtension::RecordSizeLimit(_) => {
                        extensions.push(28); // record_size_limit
                    }
                    tls_parser::TlsExtension::SessionTicket(_) => {
                        extensions.push(35); // session_ticket
                    }
                    tls_parser::TlsExtension::KeyShare(_) => {
                        extensions.push(51); // key_share
                    }
                    tls_parser::TlsExtension::KeyShareOld(_) => {
                        extensions.push(40); // key_share_old
                    }
                    tls_parser::TlsExtension::PreSharedKey(_) => {
                        extensions.push(41); // pre_shared_key
                    }
                    tls_parser::TlsExtension::EarlyData(_) => {
                        extensions.push(42); // early_data
                    }
                    tls_parser::TlsExtension::Cookie(_) => {
                        extensions.push(44); // cookie
                    }
                    tls_parser::TlsExtension::PskExchangeModes(_) => {
                        extensions.push(45); // psk_key_exchange_modes
                    }
                    tls_parser::TlsExtension::OidFilters(_) => {
                        extensions.push(48); // oid_filters
                    }
                    tls_parser::TlsExtension::PostHandshakeAuth => {
                        extensions.push(49); // post_handshake_auth
                    }
                    tls_parser::TlsExtension::Heartbeat(_) => {
                        extensions.push(15); // heartbeat
                    }
                    tls_parser::TlsExtension::SignedCertificateTimestamp(_) => {
                        extensions.push(18); // signed_certificate_timestamp
                    }
                    tls_parser::TlsExtension::Padding(_) => {
                        extensions.push(21); // padding
                    }
                    tls_parser::TlsExtension::Grease(ext_type, _) => {
                        // GREASE扩展，添加到扩展列表中
                        extensions.push(ext_type);
                    }
                    tls_parser::TlsExtension::Unknown(ext_type, _) => {
                        // 未知扩展类型，添加到扩展列表中
                        let ext_type_u16: u16 = ext_type.into();
                        extensions.push(ext_type_u16);
                    }
                    tls_parser::TlsExtension::RenegotiationInfo(_) => {
                        // 重新协商信息扩展 (0xff01)
                        extensions.push(0xff01);
                    }
                    tls_parser::TlsExtension::ExtendedMasterSecret => {
                        // 扩展主密钥扩展 (0x0017)
                        extensions.push(0x17);
                    }
                    _ => {
                        // 其他扩展类型
                    }
                }
            }
        }
        Err(_) => {
            // 解析失败，返回空值
        }
    }
    
    (extensions, elliptic_curves, ec_point_formats, signature_algorithms)
}