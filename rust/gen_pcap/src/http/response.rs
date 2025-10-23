// HTTP响应相关

use std::collections::HashMap;

// HTTP状态码枚举
#[derive(Debug, Clone)]
pub enum HttpStatusCode {
    Ok,
    NotFound,
    InternalServerError,
    BadRequest,
    Unauthorized,
    Forbidden,
    Custom(u16),
}

impl HttpStatusCode {
    pub fn code(&self) -> u16 {
        match self {
            HttpStatusCode::Ok => 200,
            HttpStatusCode::NotFound => 404,
            HttpStatusCode::InternalServerError => 500,
            HttpStatusCode::BadRequest => 400,
            HttpStatusCode::Unauthorized => 401,
            HttpStatusCode::Forbidden => 403,
            HttpStatusCode::Custom(code) => *code,
        }
    }

    pub fn reason_phrase(&self) -> &'static str {
        match self {
            HttpStatusCode::Ok => "OK",
            HttpStatusCode::NotFound => "Not Found",
            HttpStatusCode::InternalServerError => "Internal Server Error",
            HttpStatusCode::BadRequest => "Bad Request",
            HttpStatusCode::Unauthorized => "Unauthorized",
            HttpStatusCode::Forbidden => "Forbidden",
            HttpStatusCode::Custom(_) => "Custom",
        }
    }
}

// HTTP响应结构体
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub version: HttpVersion,
    pub status_code: HttpStatusCode,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

// 导入HttpVersion
use super::request::HttpVersion;

impl HttpResponse {
    pub fn new(status_code: HttpStatusCode) -> Self {
        Self {
            version: HttpVersion::Http1_1,
            status_code,
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn with_version(mut self, version: HttpVersion) -> Self {
        self.version = version;
        self
    }

    pub fn add_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut response = String::new();

        // 状态行
        response.push_str(&format!("{} {} {}\r\n",
            self.version.as_str(),
            self.status_code.code(),
            self.status_code.reason_phrase()
        ));

        // 添加默认头部
        let mut headers = self.headers.clone();
        if !headers.contains_key("Server") {
            headers.insert("Server".to_string(), "gen_pcap/1.0".to_string());
        }
        if let Some(ref body) = self.body {
            headers.insert("Content-Length".to_string(), body.len().to_string());
        }

        // 头部
        for (key, value) in &headers {
            response.push_str(&format!("{}: {}\r\n", key, value));
        }

        // 空行
        response.push_str("\r\n");

        let mut result = response.into_bytes();

        // 添加响应体
        if let Some(ref body) = self.body {
            result.extend_from_slice(body);
        }

        result
    }
}