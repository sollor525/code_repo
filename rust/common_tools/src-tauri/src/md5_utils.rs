use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Debug)]
pub struct Md5Request {
    pub text: Option<String>,
    pub file_path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Md5Response {
    pub success: bool,
    pub md5_hash: Option<String>,
    pub input_type: String,
    pub input_size: Option<usize>,
    pub error: Option<String>,
}

/// 计算字符串的 MD5 哈希值
pub fn calculate_text_md5(text: &str) -> String {
    let digest = md5::compute(text);
    format!("{:x}", digest)
}

/// 计算文件的 MD5 哈希值
pub fn calculate_file_md5(file_path: &str) -> Result<String, String> {
    match fs::read(file_path) {
        Ok(content) => {
            let digest = md5::compute(&content);
            Ok(format!("{:x}", digest))
        }
        Err(e) => Err(format!("读取文件失败: {}", e)),
    }
}

/// 处理 MD5 计算请求
pub fn process_md5_request(request: Md5Request) -> Md5Response {
    if let Some(text) = request.text {
        // 处理文本输入
        let md5_hash = calculate_text_md5(&text);
        Md5Response {
            success: true,
            md5_hash: Some(md5_hash),
            input_type: "text".to_string(),
            input_size: Some(text.len()),
            error: None,
        }
    } else if let Some(file_path) = request.file_path {
        // 处理文件输入
        match calculate_file_md5(&file_path) {
            Ok(md5_hash) => {
                // 获取文件大小
                let file_size = fs::metadata(&file_path)
                    .map(|m| m.len() as usize)
                    .unwrap_or(0);
                
                Md5Response {
                    success: true,
                    md5_hash: Some(md5_hash),
                    input_type: "file".to_string(),
                    input_size: Some(file_size),
                    error: None,
                }
            }
            Err(e) => Md5Response {
                success: false,
                md5_hash: None,
                input_type: "file".to_string(),
                input_size: None,
                error: Some(e),
            },
        }
    } else {
        // 没有提供输入
        Md5Response {
            success: false,
            md5_hash: None,
            input_type: "none".to_string(),
            input_size: None,
            error: Some("请提供文本或文件路径".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_md5() {
        let text = "Hello, World!";
        let hash = calculate_text_md5(text);
        assert_eq!(hash, "65a8e27d8879283831b664bd8b7f0ad4");
    }

    #[test]
    fn test_empty_text_md5() {
        let text = "";
        let hash = calculate_text_md5(text);
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_chinese_text_md5() {
        let text = "你好，世界！";
        let hash = calculate_text_md5(text);
        assert_eq!(hash, "5082079d92a8ef985f59e001d445ff20");
    }
}
