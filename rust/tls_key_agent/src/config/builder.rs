/**
 * @file builder.rs
 * @brief 配置构建器 - 提供便捷的配置构建方法
 * @author sollor525@hotmail.com
 * @version 0.1.0
 * @date 2023-11-04
 */
use super::*;
use std::path::Path;

/// 配置构建器
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// 创建新的配置构建器
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// 设置Agent配置
    pub fn with_agent_config<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut AgentConfig),
    {
        f(&mut self.config.agent);
        self
    }

    /// 设置提取配置
    pub fn with_extraction_config<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut ExtractionConfig),
    {
        f(&mut self.config.extraction);
        self
    }

    /// 设置传输配置
    pub fn with_transport_config<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut TransportConfig),
    {
        f(&mut self.config.transport);
        self
    }

    /// 添加过滤规则
    pub fn add_filter(mut self, filter: FilterRule) -> Self {
        self.config.filters.push(filter);
        self
    }

    /// 启用TCP传输
    pub fn enable_tcp_transport(mut self, host: &str, port: u16) -> Self {
        if !self.config.transport.enabled_transports.contains(&TransportType::Tcp) {
            self.config.transport.enabled_transports.push(TransportType::Tcp);
        }
        self.config.transport.tcp.server_host = host.to_string();
        self.config.transport.tcp.server_port = port;
        self
    }

    /// 启用文件传输
    pub fn enable_file_transport(mut self, path: &str) -> Self {
        if !self.config.transport.enabled_transports.contains(&TransportType::File) {
            self.config.transport.enabled_transports.push(TransportType::File);
        }
        self.config.transport.file.enabled = true;
        self.config.transport.file.output_path = path.to_string();
        self
    }

    /// 启用文件轮转
    pub fn enable_file_rotation(mut self, max_size: u64, max_files: usize) -> Self {
        self.config.transport.file.rotation = true;
        self.config.transport.file.max_file_size = max_size;
        self.config.transport.file.max_files = max_files;
        self
    }

    /// 添加端口过滤规则
    pub fn add_port_filter(mut self, name: &str, port: u16, protocol: Protocol) -> Self {
        let filter = FilterRule {
            name: name.to_string(),
            enabled: true,
            five_tuple: FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: Some(port),
                protocol: Some(protocol),
            },
            process_name: None,
            pid: None,
        };
        self.config.filters.push(filter);
        self
    }

    /// 添加进程过滤规则
    pub fn add_process_filter(mut self, name: &str, process_pattern: &str) -> Self {
        let filter = FilterRule {
            name: name.to_string(),
            enabled: true,
            five_tuple: FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
            },
            process_name: Some(process_pattern.to_string()),
            pid: None,
        };
        self.config.filters.push(filter);
        self
    }

    /// 构建配置
    pub fn build(self) -> Result<Config> {
        self.config.validate()?;
        Ok(self.config)
    }

    /// 构建并保存配置到文件
    pub fn build_and_save<P: AsRef<Path>>(self, path: P) -> Result<Config> {
        let config = self.build()?;
        config.save_to_file(path)?;
        Ok(config)
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 预定义配置模板
pub mod presets {
    use super::*;

    /// 开发环境配置
    pub fn development() -> ConfigBuilder {
        ConfigBuilder::new()
            .enable_file_transport("./dev_tls_keys.log")
            .enable_file_rotation(10 * 1024 * 1024, 5) // 10MB, 5个文件
            .add_port_filter("http", 80, Protocol::TCP)
            .add_port_filter("https", 443, Protocol::TCP)
            .add_process_filter("web_servers", "nginx|apache|httpd")
    }

    /// 生产环境配置
    pub fn production() -> ConfigBuilder {
        ConfigBuilder::new()
            .enable_tcp_transport("127.0.0.1", 9999)
            .enable_file_transport("/var/log/tls_keys.log")
            .enable_file_rotation(500 * 1024 * 1024, 20) // 500MB, 20个文件
            .add_port_filter("http", 80, Protocol::TCP)
            .add_port_filter("https", 443, Protocol::TCP)
            .add_process_filter("web_servers", "nginx|apache|httpd|lighttpd")
            .with_agent_config(|agent| {
                agent.log_level = "warn".to_string();
                agent.buffer_pool_size = 5000;
                agent.buffer_size = 16384;
            })
    }

    /// 调试配置
    pub fn debug() -> ConfigBuilder {
        ConfigBuilder::new()
            .enable_file_transport("./debug_tls_keys.log")
            .add_port_filter("http", 80, Protocol::TCP)
            .add_port_filter("https", 443, Protocol::TCP)
            .add_port_filter("smtp", 25, Protocol::TCP)
            .add_port_filter("smtps", 587, Protocol::TCP)
            .add_port_filter("imaps", 993, Protocol::TCP)
            .add_port_filter("pop3s", 995, Protocol::TCP)
            .add_process_filter("all_servers", "nginx|apache|httpd|postfix|dovecot")
            .with_extraction_config(|extraction| {
                extraction.enabled = true;
                extraction.capture_client_random = true;
                extraction.capture_master_secret = true;
                extraction.capture_session_ticket = true;
            })
            .with_agent_config(|agent| {
                agent.log_level = "debug".to_string();
                agent.buffer_pool_size = 1000;
                agent.buffer_size = 8192;
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_builder_basic() {
        let config = ConfigBuilder::new()
            .enable_tcp_transport("127.0.0.1", 9999)
            .add_port_filter("test", 8080, Protocol::TCP)
            .build()
            .unwrap();

        assert_eq!(config.transport.tcp.server_port, 9999);
        assert_eq!(config.filters.len(), 4); // 3默认 + 1新增
        assert!(config.filters.iter().any(|f| f.name == "test"));
    }

    #[test]
    fn test_development_preset() {
        let config = presets::development().build().unwrap();

        assert!(config.transport.enabled_transports.contains(&TransportType::File));
        assert!(config.transport.file.rotation);
        assert_eq!(config.transport.file.max_file_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_production_preset() {
        let config = presets::production().build().unwrap();

        assert!(config.transport.enabled_transports.contains(&TransportType::Tcp));
        assert!(config.transport.enabled_transports.contains(&TransportType::File));
        assert_eq!(config.agent.log_level, "warn");
        assert_eq!(config.agent.buffer_pool_size, 5000);
    }

    #[test]
    fn test_debug_preset() {
        let config = presets::debug().build().unwrap();

        assert_eq!(config.agent.log_level, "debug");
        assert!(config.extraction.capture_session_ticket);
        assert!(config.filters.iter().any(|f| f.name.contains("smtp")));
    }

    #[test]
    fn test_save_config() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.toml");

        let _config = ConfigBuilder::new()
            .enable_file_transport("./test.log")
            .build_and_save(&config_path)
            .unwrap();

        assert!(config_path.exists());

        // 验证保存的配置可以正确加载
        let loaded_config = Config::from_file(&config_path).unwrap();
        assert_eq!(loaded_config.transport.file.output_path, "./test.log");
    }
}