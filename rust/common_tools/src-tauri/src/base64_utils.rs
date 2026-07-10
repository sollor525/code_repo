//! Base64 编解码：文本 / 十六进制 ⇄ Base64。
//!
//! 纯逻辑，不依赖外部 base64 crate：手写编解码表，支持标准字母表（`+/`）与
//! URL 安全字母表（`-_`）、可选填充 `=`、可选按 N 字符换行（MIME 风格 76）。
//! 解码时同时接受两种字母表、忽略空白与换行、允许缺失填充，并回报实际识别到的
//! 字母表；解码结果非 UTF-8 时给出十六进制转储。

use serde::{Deserialize, Serialize};

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// 十六进制转储中最多展示的字节数
const DUMP_LIMIT: usize = 4096;

// =============================  DTO  =============================

fn default_text() -> String {
    "text".to_string()
}
fn default_auto() -> String {
    "auto".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
pub struct Base64EncodeRequest {
    pub input: String,
    /// text | hex
    #[serde(default = "default_text")]
    pub input_format: String,
    /// 使用 URL 安全字母表（`-_`）
    #[serde(default)]
    pub url_safe: bool,
    /// 是否补齐 `=`
    #[serde(default = "default_true")]
    pub padding: bool,
    /// 每 N 个字符换行；0 表示不换行
    #[serde(default)]
    pub line_wrap: usize,
}

#[derive(Serialize, Debug)]
pub struct Base64EncodeResponse {
    pub result: String,
    pub input_bytes: usize,
    pub output_length: usize,
    pub alphabet: String,
    pub padded: bool,
}

#[derive(Deserialize)]
pub struct Base64DecodeRequest {
    pub input: String,
    /// auto | text | hex
    #[serde(default = "default_auto")]
    pub output_format: String,
}

#[derive(Serialize, Debug)]
pub struct Base64DecodeResponse {
    /// 按 `output_format` 决定的展示内容（文本或十六进制转储）
    pub result: String,
    pub is_utf8: bool,
    pub byte_length: usize,
    /// 连续小写十六进制，便于复制
    pub hex: String,
    pub alphabet: String,
    /// 实际采用的输出格式：text | hex
    pub output_format: String,
    pub note: Option<String>,
}

// =============================  编码  =============================

/// 把字节序列编码为 Base64。
pub fn encode(data: &[u8], url_safe: bool, padding: bool, line_wrap: usize) -> String {
    let table = if url_safe { URL } else { STD };
    // 每 3 字节 → 4 字符
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);

    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(table[(n >> 18) as usize & 0x3F] as char);
        out.push(table[(n >> 12) as usize & 0x3F] as char);
        // 后两个字符按实际字节数决定是数据还是填充
        if chunk.len() > 1 {
            out.push(table[(n >> 6) as usize & 0x3F] as char);
        } else if padding {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[n as usize & 0x3F] as char);
        } else if padding {
            out.push('=');
        }
    }

    if line_wrap > 0 {
        wrap_lines(&out, line_wrap)
    } else {
        out
    }
}

/// 每 `width` 个字符插入一个换行（末行不带换行）
fn wrap_lines(s: &str, width: usize) -> String {
    let bytes = s.as_bytes(); // Base64 输出全为 ASCII，按字节切分安全
    let mut out = String::with_capacity(s.len() + s.len() / width + 1);
    for (i, chunk) in bytes.chunks(width).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
    }
    out
}

// =============================  解码  =============================

/// 单个 Base64 字符 → 6 bit 值（同时接受两种字母表）
fn decode_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// 解码结果：字节内容 + 识别到的字母表 + 可选提示
pub struct Decoded {
    pub bytes: Vec<u8>,
    pub alphabet: String,
    pub note: Option<String>,
}

/// 把 Base64 字符串解码为字节。宽松策略：忽略空白/换行、允许缺失填充。
pub fn decode(input: &str) -> Result<Decoded, String> {
    let mut vals: Vec<u8> = Vec::with_capacity(input.len());
    let mut pad = 0usize;
    let mut saw_std = false;
    let mut saw_url = false;

    for (i, b) in input.bytes().enumerate() {
        match b {
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            b'=' => {
                pad += 1;
                continue;
            }
            _ => {}
        }
        // 填充符之后不应再出现数据字符
        if pad > 0 {
            return Err(format!(
                "位置 {}：填充符「=」之后不应再有数据字符",
                i + 1
            ));
        }
        match b {
            b'+' | b'/' => saw_std = true,
            b'-' | b'_' => saw_url = true,
            _ => {}
        }
        let v = decode_val(b).ok_or_else(|| {
            format!(
                "位置 {}：无效的 Base64 字符「{}」",
                i + 1,
                escape_char(b)
            )
        })?;
        vals.push(v);
    }

    if vals.is_empty() {
        return Err("请输入 Base64 字符串".to_string());
    }
    if pad > 2 {
        return Err(format!("填充符「=」最多 2 个，当前 {pad} 个"));
    }
    if vals.len() % 4 == 1 {
        return Err(format!(
            "Base64 长度无效：有效字符 {} 个，除以 4 余 1，最后 1 个字符无法解码",
            vals.len()
        ));
    }

    let mut bytes = Vec::with_capacity(vals.len() / 4 * 3 + 3);
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for v in &vals {
        acc = (acc << 6) | u32::from(*v);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            bytes.push((acc >> nbits) as u8);
        }
    }

    let alphabet = match (saw_std, saw_url) {
        (true, true) => "混合（同时含 +/ 与 -_，可能已损坏）".to_string(),
        (true, false) => "标准（+/）".to_string(),
        (false, true) => "URL 安全（-_）".to_string(),
        (false, false) => "标准 / URL 安全（无区分字符）".to_string(),
    };

    // 末尾冗余比特应为 0，否则属于非规范编码（不影响解码结果）
    let leftover = acc & ((1u32 << nbits) - 1);
    let mut note = None;
    if nbits > 0 && leftover != 0 {
        note = Some("末尾冗余比特非零，属非规范 Base64 编码（已忽略）".to_string());
    }
    if saw_std && saw_url {
        note = Some("输入同时包含 +/ 与 -_ 两种字母表的字符，结果可能不正确".to_string());
    }

    Ok(Decoded {
        bytes,
        alphabet,
        note,
    })
}

fn escape_char(b: u8) -> String {
    if (0x20..0x7F).contains(&b) {
        (b as char).to_string()
    } else {
        format!("0x{b:02x}")
    }
}

// =============================  辅助  =============================

/// 解析十六进制输入：忽略空白、`:`、`-`、`,` 与 `0x` 前缀
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-' && *c != ',')
        .collect();
    if cleaned.is_empty() {
        return Err("十六进制输入为空".to_string());
    }
    if cleaned.len() % 2 != 0 {
        return Err(format!(
            "十六进制字符个数为奇数（{}），无法组成完整字节",
            cleaned.len()
        ));
    }
    hex::decode(&cleaned).map_err(|e| format!("十六进制解析失败：{e}"))
}

/// 十六进制转储：`偏移  16 字节 hex  |ASCII|`
fn hex_dump(bytes: &[u8]) -> String {
    let shown = bytes.len().min(DUMP_LIMIT);
    let mut out = String::new();
    for (i, chunk) in bytes[..shown].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..0x7F).contains(&b) { b as char } else { '.' })
            .collect();
        out.push_str(&format!(
            "{:08x}  {:<47}  |{}|\n",
            i * 16,
            hex.join(" "),
            ascii
        ));
    }
    if bytes.len() > shown {
        out.push_str(&format!(
            "... 共 {} 字节，仅显示前 {} 字节\n",
            bytes.len(),
            shown
        ));
    }
    out
}

// =============================  对外接口  =============================

pub fn process_encode(req: &Base64EncodeRequest) -> Result<Base64EncodeResponse, String> {
    let data: Vec<u8> = match req.input_format.as_str() {
        "text" => req.input.as_bytes().to_vec(),
        "hex" => parse_hex(&req.input)?,
        other => return Err(format!("未知的输入格式：{other}")),
    };
    if data.is_empty() {
        return Err("请输入待编码内容".to_string());
    }
    if req.line_wrap > 1000 {
        return Err("换行宽度需在 0-1000 之间（0 表示不换行）".to_string());
    }

    let result = encode(&data, req.url_safe, req.padding, req.line_wrap);
    Ok(Base64EncodeResponse {
        output_length: result.chars().filter(|c| *c != '\n').count(),
        input_bytes: data.len(),
        alphabet: if req.url_safe {
            "URL 安全（-_）".to_string()
        } else {
            "标准（+/）".to_string()
        },
        padded: req.padding,
        result,
    })
}

pub fn process_decode(req: &Base64DecodeRequest) -> Result<Base64DecodeResponse, String> {
    let decoded = decode(&req.input)?;
    let text = String::from_utf8(decoded.bytes.clone()).ok();
    let is_utf8 = text.is_some();

    // auto：能解成 UTF-8 就给文本，否则退回十六进制转储
    let want_text = match req.output_format.as_str() {
        "text" => true,
        "hex" => false,
        "auto" => is_utf8,
        other => return Err(format!("未知的输出格式：{other}")),
    };

    let mut note = decoded.note;
    let (result, output_format) = if want_text {
        match text {
            Some(t) => (t, "text"),
            None => {
                note = Some("解码结果不是合法 UTF-8 文本，已改为十六进制展示".to_string());
                (hex_dump(&decoded.bytes), "hex")
            }
        }
    } else {
        (hex_dump(&decoded.bytes), "hex")
    };

    Ok(Base64DecodeResponse {
        result,
        is_utf8,
        byte_length: decoded.bytes.len(),
        hex: hex::encode(&decoded.bytes),
        alphabet: decoded.alphabet,
        output_format: output_format.to_string(),
        note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 第 10 节的测试向量
    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, b64) in cases {
            assert_eq!(encode(plain.as_bytes(), false, true, 0), b64, "编码 {plain}");
            if !b64.is_empty() {
                assert_eq!(decode(b64).unwrap().bytes, plain.as_bytes(), "解码 {b64}");
            }
        }
    }

    #[test]
    fn url_safe_alphabet_differs_from_standard() {
        // 0xFB 0xFF 会同时用到第 62、63 号字符
        let data = [0xfb, 0xff, 0xfe];
        assert_eq!(encode(&data, false, true, 0), "+//+");
        assert_eq!(encode(&data, true, true, 0), "-__-");
        // 两种字母表都能解回原始字节
        assert_eq!(decode("+//+").unwrap().bytes, data);
        assert_eq!(decode("-__-").unwrap().bytes, data);
    }

    #[test]
    fn detects_alphabet_and_flags_mixing() {
        assert_eq!(decode("+//+").unwrap().alphabet, "标准（+/）");
        assert_eq!(decode("-__-").unwrap().alphabet, "URL 安全（-_）");
        assert!(decode("Zm9v").unwrap().alphabet.contains("无区分字符"));
        let mixed = decode("-//-").unwrap();
        assert!(mixed.alphabet.contains("混合"));
        assert!(mixed.note.unwrap().contains("两种字母表"));
    }

    #[test]
    fn padding_optional_on_encode_and_decode() {
        assert_eq!(encode(b"f", false, false, 0), "Zg");
        assert_eq!(encode(b"fo", false, false, 0), "Zm8");
        // 缺失填充仍可解码
        assert_eq!(decode("Zg").unwrap().bytes, b"f");
        assert_eq!(decode("Zm9vYg").unwrap().bytes, b"foob");
    }

    #[test]
    fn decode_ignores_whitespace_and_newlines() {
        assert_eq!(decode("Zm9v YmFy").unwrap().bytes, b"foobar");
        assert_eq!(decode("Zm9v\nYmFy\r\n").unwrap().bytes, b"foobar");
        assert_eq!(decode("  Zm9vYmFy  ").unwrap().bytes, b"foobar");
    }

    #[test]
    fn line_wrap_splits_output_and_round_trips() {
        let wrapped = encode(&[b'a'; 60], false, true, 76);
        assert!(wrapped.contains('\n'));
        assert!(wrapped.lines().all(|l| l.len() <= 76));
        assert_eq!(decode(&wrapped).unwrap().bytes, vec![b'a'; 60]);
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(decode("Zm9v!").is_err()); // 非法字符
        assert!(decode("Zm9vY").is_err()); // 长度 % 4 == 1
        assert!(decode("Zg==Zg==").is_err()); // 填充后仍有数据
        assert!(decode("Zg===").is_err()); // 填充符过多
        assert!(decode("   ").is_err()); // 空输入
    }

    #[test]
    fn round_trip_all_byte_values() {
        let data: Vec<u8> = (0..=255u8).collect();
        for url_safe in [false, true] {
            for padding in [false, true] {
                let enc = encode(&data, url_safe, padding, 0);
                assert_eq!(decode(&enc).unwrap().bytes, data, "url={url_safe} pad={padding}");
            }
        }
    }

    #[test]
    fn encode_from_hex_input() {
        let req = Base64EncodeRequest {
            input: "66 6f 6f 62 61 72".to_string(),
            input_format: "hex".to_string(),
            url_safe: false,
            padding: true,
            line_wrap: 0,
        };
        let r = process_encode(&req).unwrap();
        assert_eq!(r.result, "Zm9vYmFy");
        assert_eq!(r.input_bytes, 6);

        // 0x 前缀与分隔符同样被忽略
        let req = Base64EncodeRequest {
            input: "0x66:6f-6f,62 61 72".to_string(),
            input_format: "hex".to_string(),
            url_safe: false,
            padding: true,
            line_wrap: 0,
        };
        assert_eq!(process_encode(&req).unwrap().result, "Zm9vYmFy");
    }

    #[test]
    fn encode_rejects_odd_hex() {
        let req = Base64EncodeRequest {
            input: "666".to_string(),
            input_format: "hex".to_string(),
            url_safe: false,
            padding: true,
            line_wrap: 0,
        };
        assert!(process_encode(&req).unwrap_err().contains("奇数"));
    }

    #[test]
    fn decode_binary_falls_back_to_hex_dump() {
        // 0xff 0xfe 不是合法 UTF-8
        let b64 = encode(&[0xff, 0xfe], false, true, 0);
        let req = Base64DecodeRequest {
            input: b64,
            output_format: "auto".to_string(),
        };
        let r = process_decode(&req).unwrap();
        assert!(!r.is_utf8);
        assert_eq!(r.output_format, "hex");
        assert_eq!(r.hex, "fffe");
        assert!(r.result.contains("fffe") || r.result.contains("ff fe"));
    }

    #[test]
    fn decode_text_output_of_utf8() {
        let req = Base64DecodeRequest {
            input: encode("你好，世界".as_bytes(), false, true, 0),
            output_format: "auto".to_string(),
        };
        let r = process_decode(&req).unwrap();
        assert!(r.is_utf8);
        assert_eq!(r.result, "你好，世界");
        assert_eq!(r.output_format, "text");
    }

    #[test]
    fn forcing_text_output_on_binary_notes_the_fallback() {
        let req = Base64DecodeRequest {
            input: "//4=".to_string(),
            output_format: "text".to_string(),
        };
        let r = process_decode(&req).unwrap();
        assert_eq!(r.output_format, "hex");
        assert!(r.note.unwrap().contains("UTF-8"));
    }
}
