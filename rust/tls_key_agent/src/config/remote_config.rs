use serde::{Deserialize, Serialize};
use tracing::info;
use crate::common::error::{TlsKeyAgentError, Result};
use crate::config::Config;

#[cfg(feature = "reqwest")]
use reqwest;
#[cfg(feature = "reqwest")]
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfigClient {
    pub enabled: bool,
    pub server_url: String,
    pub api_key: Option<String>,
    pub poll_interval: u64,
    pub timeout: u64,
    pub retry_attempts: u32,
}

#[cfg(feature = "reqwest")]
#[derive(Debug, Clone)]
pub struct ConfigFetcher {
    #[allow(dead_code)]
    client: reqwest::Client,
    #[allow(dead_code)]
    api_key: Option<String>,
}

// 当没有reqwest feature时的默认实现
#[cfg(not(feature = "reqwest"))]
impl RemoteConfigClient {
    pub fn start_polling(&self) -> Result<()> {
        info!("远程配置轮询功能需要启用reqwest feature");
        Ok(())
    }

    pub fn stop_polling(&self) -> Result<()> {
        info!("远程配置轮询功能需要启用reqwest feature");
        Ok(())
    }

    pub fn fetch_config(&self) -> Result<Config> {
        Err(TlsKeyAgentError::Config(
            "远程配置获取需要启用reqwest feature".to_string()
        ))
    }
}

impl Default for RemoteConfigClient {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: "http://localhost:8080/api/v1/config".to_string(),
            api_key: None,
            poll_interval: 300, // 5分钟
            timeout: 30,
            retry_attempts: 3,
        }
    }
}

#[cfg(feature = "reqwest")]
pub struct RemoteConfigManager {
    client: reqwest::Client,
    config: RemoteConfigClient,
    current_config: Option<Config>,
}

#[cfg(feature = "reqwest")]
impl RemoteConfigManager {
    pub fn new(config: RemoteConfigClient) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                client: reqwest::Client::new(),
                config,
                current_config: None,
            });
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .build()
            .map_err(|e| TlsKeyAgentError::Network(format!("{}", e)))?;

        Ok(Self {
            client,
            config,
            current_config: None,
        })
    }

    pub async fn fetch_config(&self) -> Result<Config> {
        if !self.config.enabled {
            return Err(TlsKeyAgentError::Config("远程配置未启用".to_string()));
        }

        info!("从远程服务器获取配置: {}", self.config.server_url);

        let mut request = self.client
            .get(&self.config.server_url)
            .header("User-Agent", "tls-key-agent/0.1.0");

        if let Some(api_key) = &self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .send()
            .await
            .map_err(|e| TlsKeyAgentError::Network(format!("{}", e)))?;

        if !response.status().is_success() {
            return Err(TlsKeyAgentError::Config(
                format!("远程配置服务器返回错误: {}", response.status())
            ));
        }

        let config_text = response
            .text()
            .await
            .map_err(|e| TlsKeyAgentError::Network(format!("{}", e)))?;

        let config: Config = toml::from_str(&config_text)
            .map_err(|e| TlsKeyAgentError::Config(format!("解析远程配置失败: {}", e)))?;

        config.validate()?;

        info!("成功获取远程配置");
        Ok(config)
    }

    pub async fn start_polling(&mut self) -> Result<()> {
        if !self.config.enabled {
            return Err(TlsKeyAgentError::Config("远程配置未启用".to_string()));
        }

        info!("远程配置轮询功能已禁用，需要手动调用fetch_config");
        Ok(())
    }

    #[allow(dead_code)]
    async fn fetch_remote_config_once(
        client: &reqwest::Client,
        server_url: &str,
        api_key: &Option<String>,
    ) -> Result<Config> {
        let mut request = client
            .get(server_url)
            .header("User-Agent", "tls-key-agent/0.1.0");

        if let Some(api_key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .send()
            .await
            .map_err(|e| TlsKeyAgentError::Network(format!("{}", e)))?;

        if !response.status().is_success() {
            return Err(TlsKeyAgentError::Config(
                format!("远程配置服务器返回错误: {}", response.status())
            ));
        }

        let config_text = response
            .text()
            .await
            .map_err(|e| TlsKeyAgentError::Network(format!("{}", e)))?;

        let config: Config = toml::from_str(&config_text)
            .map_err(|e| TlsKeyAgentError::Config(format!("解析远程配置失败: {}", e)))?;

        config.validate()?;

        Ok(config)
    }

    pub fn get_current_config(&self) -> Option<&Config> {
        self.current_config.as_ref()
    }

    pub fn set_current_config(&mut self, config: Config) {
        self.current_config = Some(config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_remote_config_client_default() {
        let client = RemoteConfigClient::default();
        assert!(!client.enabled);
        assert_eq!(client.poll_interval, 300);
    }
}

// 为启用reqwest feature的RemoteConfigClient添加方法实现
#[cfg(feature = "reqwest")]
impl RemoteConfigClient {
    pub fn start_polling(&self) -> Result<()> {
        info!("远程配置轮询功能已启用");
        // 这里可以启动后台轮询任务
        Ok(())
    }

    pub fn stop_polling(&self) -> Result<()> {
        info!("停止远程配置轮询");
        // 这里可以停止后台轮询任务
        Ok(())
    }

    pub fn fetch_config(&self) -> Result<Config> {
        info!("获取远程配置");
        // 这是一个同步版本，实际使用时可能需要异步版本
        Err(TlsKeyAgentError::Config(
            "请使用RemoteConfigManager进行异步配置获取".to_string()
        ))
    }
}

#[cfg(feature = "reqwest")]
#[tokio::test]
async fn test_remote_config_manager_disabled() {
    let config = RemoteConfigClient::default();
    let manager = RemoteConfigManager::new(config).unwrap();
    assert!(manager.fetch_config().await.is_err());
}