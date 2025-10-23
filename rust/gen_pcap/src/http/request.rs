// HTTP请求相关

use std::collections::HashMap;

// HTTP方法枚举
#[derive(Debug, Clone)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::GET => "GET",
            HttpMethod::POST => "POST",
            HttpMethod::PUT => "PUT",
            HttpMethod::DELETE => "DELETE",
            HttpMethod::HEAD => "HEAD",
            HttpMethod::OPTIONS => "OPTIONS",
            HttpMethod::PATCH => "PATCH",
        }
    }
}

// HTTP版本枚举
#[derive(Debug, Clone)]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
    Http2_0,
}

impl HttpVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpVersion::Http1_0 => "HTTP/1.0",
            HttpVersion::Http1_1 => "HTTP/1.1",
            HttpVersion::Http2_0 => "HTTP/2.0",
        }
    }
}

// HTTP请求结构体
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub version: HttpVersion,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    pub fn new(method: HttpMethod, uri: String) -> Self {
        Self {
            method,
            uri,
            version: HttpVersion::Http1_1,
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
        let mut request = String::new();

        // 请求行
        request.push_str(&format!("{} {} {}\r\n",
            self.method.as_str(),
            self.uri,
            self.version.as_str()
        ));

        // 添加默认头部
        let mut headers = self.headers.clone();
        if !headers.contains_key("Host") {
            headers.insert("Host".to_string(), "localhost".to_string());
        }
        if !headers.contains_key("User-Agent") {
            headers.insert("User-Agent".to_string(), "gen_pcap/1.0".to_string());
        }
        if !headers.contains_key("Accept") {
            headers.insert("Accept".to_string(), "*/*".to_string());
        }
        if let Some(ref body) = self.body {
            headers.insert("Content-Length".to_string(), body.len().to_string());
        }

        // 头部
        for (key, value) in &headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        // 空行
        request.push_str("\r\n");

        let mut result = request.into_bytes();

        // 添加请求体
        if let Some(ref body) = self.body {
            result.extend_from_slice(body);
        }

        result
    }
}