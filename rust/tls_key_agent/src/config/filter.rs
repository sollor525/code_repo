use std::net::IpAddr;
use tracing::{debug, trace};
use crate::common::session::{FiveTuple, TlsSession};
use crate::common::error::{TlsKeyAgentError, Result};
use crate::config::FilterRule;

#[derive(Debug)]
pub struct FilterEngine {
    rules: Vec<FilterRule>,
}

impl FilterEngine {
    pub fn new(rules: Vec<FilterRule>) -> Self {
        Self { rules }
    }

    pub fn should_capture_session(&self, session: &TlsSession) -> bool {
        // 如果没有规则，默认捕获所有会话
        if self.rules.is_empty() {
            debug!("没有配置过滤规则，捕获所有TLS会话");
            return true;
        }

        // 检查是否有任何启用的规则匹配
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if self.rule_matches_session(rule, session) {
                debug!("会话匹配规则 '{}'", rule.name);
                return true;
            }
        }

        trace!("会话不匹配任何过滤规则，跳过捕获");
        false
    }

    fn rule_matches_session(&self, rule: &FilterRule, session: &TlsSession) -> bool {
        // 检查五元组过滤
        if !self.five_tuple_matches(&rule.five_tuple, &session.five_tuple) {
            return false;
        }

        // 检查进程名过滤
        if let Some(ref process_name) = rule.process_name {
            if !session.process_info.process_name.contains(process_name) {
                return false;
            }
        }

        // 检查PID过滤
        if let Some(pid) = rule.pid {
            if session.process_info.pid != pid {
                return false;
            }
        }

        true
    }

    fn five_tuple_matches(&self, filter: &crate::config::FiveTupleFilter, tuple: &FiveTuple) -> bool {
        // 检查源IP
        if let Some(ref src_ip_str) = filter.src_ip {
            match src_ip_str.parse::<IpAddr>() {
                Ok(src_ip) => {
                    if !src_ip.is_unspecified() && src_ip != tuple.src_ip {
                        return false;
                    }
                }
                Err(_) => {
                    debug!("无效的源IP地址格式: {}", src_ip_str);
                    return false;
                }
            }
        }

        // 检查源端口
        if let Some(src_port) = filter.src_port {
            if src_port != 0 && src_port != tuple.src_port {
                return false;
            }
        }

        // 检查目标IP
        if let Some(ref dst_ip_str) = filter.dst_ip {
            match dst_ip_str.parse::<IpAddr>() {
                Ok(dst_ip) => {
                    if !dst_ip.is_unspecified() && dst_ip != tuple.dst_ip {
                        return false;
                    }
                }
                Err(_) => {
                    debug!("无效的目标IP地址格式: {}", dst_ip_str);
                    return false;
                }
            }
        }

        // 检查目标端口
        if let Some(dst_port) = filter.dst_port {
            if dst_port != 0 && dst_port != tuple.dst_port {
                return false;
            }
        }

        // 检查协议
        if let Some(ref protocol) = filter.protocol {
            if std::mem::discriminant(protocol) != std::mem::discriminant(&tuple.protocol) {
                return false;
            }
        }

        true
    }

    pub fn add_rule(&mut self, rule: FilterRule) {
        debug!("添加过滤规则: {}", rule.name);
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, rule_name: &str) -> bool {
        debug!("移除过滤规则: {}", rule_name);
        let initial_len = self.rules.len();
        self.rules.retain(|rule| rule.name != rule_name);
        self.rules.len() != initial_len
    }

    pub fn enable_rule(&mut self, rule_name: &str) -> bool {
        for rule in &mut self.rules {
            if rule.name == rule_name {
                rule.enabled = true;
                debug!("启用过滤规则: {}", rule_name);
                return true;
            }
        }
        false
    }

    pub fn disable_rule(&mut self, rule_name: &str) -> bool {
        for rule in &mut self.rules {
            if rule.name == rule_name {
                rule.enabled = false;
                debug!("禁用过滤规则: {}", rule_name);
                return true;
            }
        }
        false
    }

    pub fn get_rules(&self) -> &[FilterRule] {
        &self.rules
    }

    pub fn get_enabled_rules(&self) -> Vec<&FilterRule> {
        self.rules.iter().filter(|rule| rule.enabled).collect()
    }

    pub fn stats(&self) -> FilterStats {
        let total_rules = self.rules.len();
        let enabled_rules = self.rules.iter().filter(|rule| rule.enabled).count();

        FilterStats {
            total_rules,
            enabled_rules,
            disabled_rules: total_rules - enabled_rules,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterStats {
    pub total_rules: usize,
    pub enabled_rules: usize,
    pub disabled_rules: usize,
}

impl FilterEngine {
    pub fn from_config(rules: Vec<FilterRule>) -> Result<Self> {
        // 验证规则
        for rule in &rules {
            if rule.name.is_empty() {
                return Err(TlsKeyAgentError::Config("过滤规则名称不能为空".to_string()));
            }
        }

        // 检查规则名称重复
        let mut names = std::collections::HashSet::new();
        for rule in &rules {
            if !names.insert(&rule.name) {
                return Err(TlsKeyAgentError::Config(
                    format!("过滤规则名称重复: {}", rule.name)
                ));
            }
        }

        Ok(Self { rules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_session() -> TlsSession {
        TlsSession::new(
            vec![0u8; 32], // client_random
            vec![0u8; 48], // master_secret
            FiveTuple {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 12345,
                dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                dst_port: 443,
                protocol: crate::common::session::Protocol::TCP,
            },
            crate::common::session::ProcessInfo {
                pid: 1234,
                process_name: "nginx".to_string(),
                command_line: "nginx -c /etc/nginx/nginx.conf".to_string(),
            },
        )
    }

    #[test]
    fn test_filter_engine_empty_rules() {
        let engine = FilterEngine::new(vec![]);
        let session = create_test_session();
        assert!(engine.should_capture_session(&session));
    }

    #[test]
    fn test_filter_engine_port_match() {
        let rule = FilterRule {
            name: "port_443".to_string(),
            enabled: true,
            five_tuple: crate::config::FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: Some(443),
                protocol: None,
            },
            process_name: None,
            pid: None,
        };

        let engine = FilterEngine::new(vec![rule]);
        let session = create_test_session();
        assert!(engine.should_capture_session(&session));
    }

    #[test]
    fn test_filter_engine_process_name_match() {
        let rule = FilterRule {
            name: "nginx_only".to_string(),
            enabled: true,
            five_tuple: crate::config::FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: None,
                protocol: None,
            },
            process_name: Some("nginx".to_string()),
            pid: None,
        };

        let engine = FilterEngine::new(vec![rule]);
        let session = create_test_session();
        assert!(engine.should_capture_session(&session));
    }

    #[test]
    fn test_filter_engine_disabled_rule() {
        let rule = FilterRule {
            name: "disabled_rule".to_string(),
            enabled: false,
            five_tuple: crate::config::FiveTupleFilter {
                src_ip: None,
                src_port: None,
                dst_ip: None,
                dst_port: Some(443),
                protocol: None,
            },
            process_name: None,
            pid: None,
        };

        let engine = FilterEngine::new(vec![rule]);
        let session = create_test_session();
        assert!(!engine.should_capture_session(&session));
    }
}