//! 主检测引擎模块
//! 
//! 协调协议检测、规则匹配和结果生成的核心模块。
//! 这是整个Web扫描检测系统的中央控制器。

// 导入错误处理类型
use crate::error::Result;
// 导入协议检测相关类型
use crate::protocol::{Protocol, ProtocolDetector};
// 导入规则管理相关类型
use crate::rules::{RuleAction, RuleManager, Rule};
// 导入统计收集器
use crate::stats::StatsCollector;
// 导入Hyperscan相关类型
use crate::hyperscan::{HyperscanCompiler, HyperscanScanner};
// 导入高性能读写锁（比标准库的RwLock更快）
use parking_lot::RwLock;
// 导入原子引用计数智能指针，用于多线程共享数据
use std::sync::Arc;

/// Web扫描动作枚举
/// 
/// 定义检测到威胁时应该执行的动作。
/// 这是对外暴露的动作类型，与内部的RuleAction对应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]  // C兼容的内存布局
pub enum WebScanAction {
    None = 0,   // 无动作
    Alert = 1,  // 仅告警
    Drop = 2,   // 丢弃数据包
    Reset = 3,  // 发送TCP重置
}

// 实现从RuleAction到WebScanAction的转换
// From trait允许使用.into()方法进行类型转换
impl From<RuleAction> for WebScanAction {
    fn from(action: RuleAction) -> Self {
        // 使用模式匹配进行一对一转换
        match action {
            RuleAction::None => WebScanAction::None,
            RuleAction::Alert => WebScanAction::Alert,
            RuleAction::Drop => WebScanAction::Drop,
            RuleAction::Reset => WebScanAction::Reset,
        }
    }
}

/// Web扫描检测结果结构体
/// 
/// 包含一次检测操作的完整结果信息，包括是否匹配、
/// 匹配的规则、建议的动作等。
#[derive(Debug, Clone)]
#[repr(C)]  // C兼容的内存布局
pub struct WebScanResult {
    pub is_matched: bool,           // 是否匹配到规则
    pub rule_id: u32,              // 匹配的规则ID（如果匹配的话）
    pub action: WebScanAction,      // 建议执行的动作
    pub content_length: u32,        // 检测内容的长度
    pub protocol: Protocol,         // 检测到的协议类型
    pub confidence: u8,             // 协议检测的置信度（0-100）
}

// 为WebScanResult实现Default trait
// 提供默认的"无匹配"结果
impl Default for WebScanResult {
    fn default() -> Self {
        Self {
            is_matched: false,                  // 默认未匹配
            rule_id: 0,                        // 无规则ID
            action: WebScanAction::None,       // 无动作
            content_length: 0,                 // 无内容
            protocol: Protocol::Unknown,       // 未知协议
            confidence: 0,                     // 零置信度
        }
    }
}

/// Web扫描检测引擎
///
/// 这是整个检测系统的核心，协调各个组件的工作。
/// 包含协议检测器、规则管理器、统计收集器和Hyperscan扫描器等。
/// 会话管理由外部程序负责，此引擎专注于单次数据包检测。
pub struct WebScanEngine {
    protocol_detector: ProtocolDetector,        // 协议检测器
    rule_manager: Arc<RwLock<RuleManager>>,     // 规则管理器（线程安全）
    stats: Arc<StatsCollector>,         // 统计收集器（线程安全）
    hyperscan_scanner: Option<Arc<HyperscanScanner>>,    // Hyperscan扫描器（将在规则加载后初始化）
    enabled: bool,                              // 引擎是否启用
    default_action: WebScanAction,              // 默认动作
}

impl Default for WebScanEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl WebScanEngine {
    /// 创建新的Web扫描引擎实例
    ///
    /// 初始化所有组件，设置默认配置。Hyperscan将在规则加载后初始化。
    /// Arc<RwLock<T>>模式允许多线程安全地共享和修改数据。
    pub fn new() -> Self {
        Self {
            protocol_detector: ProtocolDetector::new(),
            // Arc::new()创建原子引用计数智能指针
            // RwLock::new()创建读写锁，允许多个读者或一个写者
            rule_manager: Arc::new(RwLock::new(RuleManager::new())),
            stats: Arc::new(StatsCollector::new()),
            hyperscan_scanner: None, // 将在规则加载后初始化
            enabled: true,           // 默认启用
            default_action: WebScanAction::Alert,       // 默认告警动作
        }
    }

    /// 使用规则文件初始化引擎
    /// 
    /// 从指定路径加载规则文件，初始化规则管理器。
    /// 
    /// # 参数
    /// * `rules_path` - 规则文件路径
    /// 
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn init_with_rules(&mut self, rules_path: &str) -> Result<()> {
        // 获取规则管理器的写锁，准备修改规则
        let count = {
            let mut rule_manager = self.rule_manager.write();
            // 从文件加载规则
            let count = rule_manager.load_rules_from_file(rules_path.as_ref())?;
            count
        };
        
        // 编译规则为Hyperscan数据库（Hyperscan始终启用）
        let rule_manager = self.rule_manager.read();
        let rules: Vec<_> = rule_manager.get_all_rules().values().cloned().collect();
        drop(rule_manager); // 显式释放锁
        self._compile_hyperscan_database(&rules)?;
        
        // 记录加载成功的规则数量
        log::info!("Loaded {} rules from {}", count, rules_path);
        Ok(())
    }

    /// 编译Hyperscan数据库
    ///
    /// 这是一个内部方法，用于将规则编译为Hyperscan数据库。
    ///
    /// # 参数
    /// * `rules` - 规则列表的引用
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    fn _compile_hyperscan_database(&mut self, rules: &[Rule]) -> Result<()> {
        // 创建Hyperscan编译器 - 专门使用流模式
        let mut compiler = HyperscanCompiler::new();

        // 添加所有规则到编译器
        for rule in rules {
            compiler.add_rule(rule)?;
        }

        // 编译数据库
        let (database, fast_database) = compiler.compile()?;

        // 创建扫描器
        let scanner = HyperscanScanner::new(database, fast_database)?;

        // 存储扫描器
        self.hyperscan_scanner = Some(Arc::new(scanner));

        log::info!("Hyperscan database compiled successfully");
        Ok(())
    }

    /// 处理数据包载荷并返回检测结果
    /// 
    /// 这是引擎的核心方法，执行完整的检测流程：
    /// 1. 协议检测
    /// 2. 内容匹配
    /// 3. 规则应用
    /// 4. 统计更新
    /// 
    /// # 参数
    /// * `payload` - 要检测的数据包载荷（字节数组）
    /// 
    /// # 返回值
    /// * `Result<WebScanResult>` - 检测结果，包含匹配信息和建议动作
    pub fn process_payload(&self, payload: &[u8]) -> Result<WebScanResult> {
        // 如果引擎未启用，返回结果但记录payload长度
        if !self.enabled {
            return Ok(WebScanResult {
                content_length: payload.len() as u32,  // 记录实际payload长度
                ..Default::default()
            });
        }

        // 更新统计信息：增加已处理的数据包计数
        self.stats.increment_packets_processed();

        // 第一步：协议检测
        // 分析数据包内容，判断是否为Web流量
        let protocol_result = self.protocol_detector.detect(payload)?;

        // 记录协议统计
        self.stats.record_protocol(protocol_result.protocol);
        
        // 只处理Web流量（HTTP、HTTPS、HTTP/2）
        // matches!宏用于模式匹配，检查协议是否为Web协议
        if !matches!(protocol_result.protocol, Protocol::Http | Protocol::Https | Protocol::Http2) {
            // 如果不是Web流量，返回结果但不进行内容检测
            // 注意：即使协议未知，也应该记录payload的实际长度
            return Ok(WebScanResult {
                protocol: protocol_result.protocol,
                confidence: protocol_result.confidence,
                content_length: payload.len() as u32,  // 记录实际payload长度
                ..Default::default()
            });
        }

        // 第二步：内容转换
        // 将字节数据转换为字符串，用于规则匹配
        let _content = match std::str::from_utf8(payload) {
            Ok(s) => s,  // 如果成功转换为UTF-8，直接使用
            Err(_) => {
                // 如果UTF-8转换失败，尝试提取可打印的ASCII字符
                // 这可以处理包含二进制数据的HTTP载荷
                let ascii_content: String = payload
                    .iter()                           // 创建字节迭代器
                    .filter(|&&b| b >= 32 && b <= 126) // 过滤出可打印ASCII字符
                    .map(|&b| b as char)              // 转换为字符
                    .collect();                       // 收集为字符串
                
                // 如果没有可打印字符，返回默认结果
                if ascii_content.is_empty() {
                    return Ok(WebScanResult {
                        protocol: protocol_result.protocol,
                        confidence: protocol_result.confidence,
                        content_length: payload.len() as u32,  // 记录实际payload长度
                        ..Default::default()
                    });
                }
                
                // 使用Box::leak避免生命周期问题
                // 将字符串转换为'static生命周期，这在检测场景中是安全的
                Box::leak(ascii_content.into_boxed_str())
            }
        };

        // 第三步：规则匹配 - 使用 Hyperscan
        let (matched_rule_id, action) = {
            // 使用 Hyperscan 进行高性能匹配（始终启用）
            match self._hyperscan_match(payload) {
                Ok(Some(rule_id)) => {
                    // 从规则管理器获取完整的规则信息
                    let rule_manager = self.rule_manager.read();
                    if let Some(rule) = rule_manager.get_rule(rule_id) {
                        (Some(rule_id), Some(rule.action))
                    } else {
                        // Hyperscan 返回了规则ID，但规则管理器中没有找到对应规则
                        (Some(rule_id), None)
                    }
                }
                Ok(None) => (None, None),
                Err(e) => {
                    // Hyperscan 匹配出错，记录错误但不中断处理
                    log::warn!("Hyperscan matching failed: {}", e);
                    (None, None)
                }
            }
        };

        // 注释：不再需要回退到regex匹配，Hyperscan始终启用
        // 保留此代码段以备需要时的PCRE fallback处理

        // 如果没有匹配的规则，返回"无匹配"结果
        if matched_rule_id.is_none() {
            return Ok(WebScanResult {
                protocol: protocol_result.protocol,
                confidence: protocol_result.confidence,
                content_length: payload.len() as u32,  // 记录内容长度
                ..Default::default()
            });
        }

        // 更新统计信息：增加匹配的数据包计数
        self.stats.increment_packets_matched();

        // 获取匹配的规则ID和动作
        let rule_id = matched_rule_id.unwrap();

        // 确定要执行的动作
        let action = if let Some(rule_action) = action {
            // 使用规则中指定的动作
            if rule_action == RuleAction::None {
                self.default_action
            } else {
                rule_action.into()  // 使用From trait转换
            }
        } else {
            // Hyperscan 匹配到了规则但找不到规则信息，使用默认动作
            log::warn!("Hyperscan matched rule ID {} but rule not found in manager", rule_id);
            self.default_action
        };

        // 根据动作类型更新相应的统计信息
        match action {
            WebScanAction::Drop => self.stats.increment_packets_dropped(),    // 丢弃计数
            WebScanAction::Reset => self.stats.increment_packets_reset(),    // 重置计数
            _ => self.stats.increment_packets_alerted(),                     // 告警计数
        }

        // 构建并返回检测结果
        Ok(WebScanResult {
            is_matched: true,                    // 标记为已匹配
            rule_id,                             // 记录匹配的规则ID
            action,                              // 建议执行的动作
            content_length: payload.len() as u32, // 内容长度
            protocol: protocol_result.protocol,   // 检测到的协议
            confidence: protocol_result.confidence, // 协议检测置信度
        })
    }


    /// 使用Hyperscan进行模式匹配
    ///
    /// # 参数
    /// * `data` - 要匹配的数据
    ///
    /// # 返回值
    /// * `Result<Option<u32>>` - 匹配的规则ID，如果没有匹配返回None
    fn _hyperscan_match(&self, data: &[u8]) -> Result<Option<u32>> {
        if let Some(ref scanner) = &self.hyperscan_scanner {
            let matches = scanner.scan_stream(data)?;

            // 对于单pattern规则，直接返回第一个匹配
            // 对于多pattern规则，需要验证完整匹配
            let rule_manager = self.rule_manager.read();

            for hyp_match in matches.iter() {
                if let Some(rule) = rule_manager.get_rule(hyp_match.rule_id) {
                    // 只对多pattern规则进行完整匹配验证
                    if rule.patterns.len() > 1 {
                        let data_str = std::str::from_utf8(data).unwrap_or("");
                        if crate::rules::Rule::does_rule_fully_match(rule, data_str) {
                            return Ok(Some(hyp_match.rule_id));
                        }
                    } else {
                        // 单pattern规则，直接相信Hyperscan的结果
                        return Ok(Some(hyp_match.rule_id));
                    }
                }
            }
        }
        Ok(None)
    }

    /// 使用Hyperscan进行模式匹配（带会话管理）
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `data` - 要匹配的数据
    /// * `is_final` - 是否为该会话的最后一个数据包
    /// * `reset_on_request_end` - 是否在请求结束时重置流（用于HTTP请求/响应流）
    ///
    /// # 返回值
    /// * `Result<Option<u32>>` - 匹配的规则ID，如果没有匹配返回None
    fn _hyperscan_match_with_session(&self, session_id: u64, data: &[u8], is_final: bool, reset_on_request_end: bool) -> Result<Option<u32>> {
        if let Some(ref scanner) = &self.hyperscan_scanner {
            let matches = scanner.scan_stream_with_session(session_id, data, is_final, reset_on_request_end)?;
            // 对于单pattern规则，直接返回第一个匹配
            // 对于多pattern规则，需要验证完整匹配
            let rule_manager = self.rule_manager.read();

            for hyp_match in matches.iter() {
                if let Some(rule) = rule_manager.get_rule(hyp_match.rule_id) {
                    // 只对多pattern规则进行完整匹配验证
                    if rule.patterns.len() > 1 {
                        let data_str = std::str::from_utf8(data).unwrap_or("");
                        if crate::rules::Rule::does_rule_fully_match(rule, data_str) {
                            return Ok(Some(hyp_match.rule_id));
                        }
                    } else {
                        // 单pattern规则，直接相信Hyperscan的结果
                        return Ok(Some(hyp_match.rule_id));
                    }
                }
            }
        }
        Ok(None)
    }

    /// 使用Hyperscan进行匹配并返回完整的WebScanResult
    fn _hyperscan_match_with_session_and_result(&self, session_id: u64, data: &[u8], is_final: bool, reset_on_request_end: bool, protocol: Option<crate::protocol::Protocol>) -> Result<WebScanResult> {
        // 如果没有提供协议，进行协议检测
        let protocol_result = if let Some(proto) = protocol {
            crate::protocol::ProtocolResult {
                protocol: proto,
                confidence: 80u8,  // 0.8 * 100 = 80%
            }
        } else {
            self.protocol_detector.detect(data)?
        };

        // 记录协议统计
        self.stats.record_protocol(protocol_result.protocol);

        // 只处理Web流量（HTTP、HTTPS、HTTP/2）
        if !matches!(protocol_result.protocol, Protocol::Http | Protocol::Https | Protocol::Http2) {
            return Ok(WebScanResult {
                protocol: protocol_result.protocol,
                confidence: protocol_result.confidence,
                content_length: data.len() as u32,
                ..Default::default()
            });
        }

        // 执行Hyperscan匹配
        let matched_rule = if let Some(ref scanner) = &self.hyperscan_scanner {
            match scanner.scan_stream_with_session(session_id, data, is_final, reset_on_request_end) {
                Ok(matches) => {
                    // 验证所有匹配的规则是否真正完整匹配
                    let rule_manager = self.rule_manager.read();
                    let mut matched_rule: Option<(u32, RuleAction)> = None;

                    for hyp_match in matches.iter() {
                        if let Some(rule) = rule_manager.get_rule(hyp_match.rule_id) {
                            // 只对多pattern规则进行完整匹配验证
                            if rule.patterns.len() > 1 {
                                let data_str = std::str::from_utf8(data).unwrap_or("");
                                if crate::rules::Rule::does_rule_fully_match(rule, data_str) {
                                    matched_rule = Some((hyp_match.rule_id, rule.action));
                                    break; // 返回第一个完整匹配的规则
                                }
                            } else {
                                // 单pattern规则，直接相信Hyperscan的结果
                                matched_rule = Some((hyp_match.rule_id, rule.action));
                                break;
                            }
                        }
                    }

                    matched_rule
                }
                Err(e) => {
                    log::warn!("Hyperscan matching failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // 如果没有匹配的规则，返回"无匹配"结果
        if matched_rule.is_none() {
            return Ok(WebScanResult {
                protocol: protocol_result.protocol,
                confidence: protocol_result.confidence,
                content_length: data.len() as u32,
                ..Default::default()
            });
        }

        // 更新统计信息：增加匹配的数据包计数
        self.stats.increment_packets_matched();

        // 获取匹配的规则ID和动作
        let (rule_id, rule_action) = matched_rule.unwrap();

        // 确定要执行的动作
        let action = if rule_action == RuleAction::None {
            self.default_action
        } else {
            rule_action.into()
        };

        // 根据动作类型更新相应的统计信息
        match action {
            WebScanAction::Drop => self.stats.increment_packets_dropped(),
            WebScanAction::Reset => self.stats.increment_packets_reset(),
            _ => self.stats.increment_packets_alerted(),
        }

        // 构建并返回检测结果
        Ok(WebScanResult {
            is_matched: true,
            rule_id,
            action,
            content_length: data.len() as u32,
            protocol: protocol_result.protocol,
            confidence: protocol_result.confidence,
        })
    }

    /// 处理数据包载荷并返回检测结果（带会话管理）
    /// 
    /// 这是引擎的核心方法，执行完整的检测流程，支持跨数据包边界匹配。
    /// 
    /// # 参数
    /// * `session_id` - 会话标识符，同一个会话使用相同的ID
    /// * `payload` - 要检测的数据包载荷（字节数组）
    /// * `is_final` - 是否为该会话的最后一个数据包
    /// * `reset_on_request_end` - 是否在请求结束时重置流（用于HTTP请求/响应流，当规则只需要匹配请求包时使用）
    /// 
    /// # 返回值
    /// * `Result<WebScanResult>` - 检测结果，包含匹配信息和建议动作
    pub fn process_payload_with_session(&self, session_id: u64, payload: &[u8], is_final: bool, reset_on_request_end: bool) -> Result<WebScanResult> {
        // 如果引擎未启用，返回结果但记录payload长度
        if !self.enabled {
            return Ok(WebScanResult {
                content_length: payload.len() as u32,  // 记录实际payload长度
                ..Default::default()
            });
        }

        // 更新统计信息：增加已处理的数据包计数
        self.stats.increment_packets_processed();

        // 流式处理：检查HTTP header完整性，处理分段逻辑
        if let Some(ref scanner) = &self.hyperscan_scanner {
            let is_first_segment = scanner.is_first_segment(session_id);
            log::debug!("Segment analysis: session={}, is_first_segment={}", session_id, is_first_segment);

            if is_first_segment {
                // 第一个分段：创建会话
                log::debug!("First segment [payload_len={}]: creating session (session: {})", payload.len(), session_id);
                let _ = scanner.scan_stream_with_session(session_id, &[], false, false)?;

                // 检查HTTP header是否完整
                if crate::hyperscan::HyperscanScanner::is_http_header_complete(payload) {
                    // HTTP header完整，进行Fast pattern匹配
                    log::debug!("First segment: HTTP header complete, performing fast pattern matching (session: {})", session_id);

                    // 进行Fast pattern匹配
                    let candidate_rules = scanner.scan_fast_patterns(session_id, payload)?;
                    let should_continue_matching = if let Some(ref candidates) = candidate_rules {
                        if candidates.is_empty() {
                            // Fast pattern没有匹配任何规则，跳过完整匹配
                            log::debug!("First segment: no fast patterns matched, skipping full matching (session: {})", session_id);
                            scanner.update_session_state(session_id, Some(crate::protocol::Protocol::Http), true, false, Some(std::collections::HashSet::new()));
                            return Ok(WebScanResult {
                                content_length: payload.len() as u32,
                                protocol: crate::protocol::Protocol::Http,
                                confidence: 80u8,
                                ..Default::default()
                            });
                        } else {
                            log::debug!("First segment: fast patterns matched {} candidate rules, proceeding with full matching (session: {})", candidates.len(), session_id);
                            true
                        }
                    } else {
                        // 没有Fast pattern数据库，直接进行完整匹配
                        log::debug!("First segment: no fast pattern database, proceeding with full matching (session: {})", session_id);
                        true
                    };

                    if should_continue_matching {
                        // 检查这是否是一个完整的HTTP请求（包含body）
                        let payload_str = std::str::from_utf8(payload).unwrap_or("");
                        if payload_str.contains("\r\n\r\n") {
                            // 有HTTP body结束标记，可能是完整请求
                            let body_start = payload_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(payload.len());
                            if body_start < payload.len() {
                                // 有body内容，可以进行完整匹配
                                log::debug!("First segment: complete HTTP request with body, performing full matching (session: {})", session_id);
                                // 累积数据到stream buffer
                                scanner.append_to_stream_buffer(session_id, payload)?;
                                scanner.update_session_state(session_id, Some(crate::protocol::Protocol::Http), true, true, candidate_rules.clone());
                                return self._hyperscan_match_with_session_and_result(session_id, payload, is_final, reset_on_request_end, Some(crate::protocol::Protocol::Http));
                            } else {
                                // 完整header但没有body，进行完整匹配（因为Fast pattern已经匹配了）
                                log::debug!("First segment: complete header with fast patterns, performing full matching (session: {})", session_id);
                                // 累积数据到stream buffer
                                scanner.append_to_stream_buffer(session_id, payload)?;
                                scanner.update_session_state(session_id, Some(crate::protocol::Protocol::Http), true, true, candidate_rules);
                                return self._hyperscan_match_with_session_and_result(session_id, payload, is_final, reset_on_request_end, Some(crate::protocol::Protocol::Http));
                            }
                        } else {
                            // HTTP header不完整
                            log::debug!("First segment: HTTP header incomplete, accumulating data (session: {})", session_id);
                            scanner.append_to_stream_buffer(session_id, payload)?;
                            scanner.update_session_state(session_id, Some(crate::protocol::Protocol::Http), true, false, None);
                            return Ok(WebScanResult {
                                content_length: payload.len() as u32,
                                protocol: crate::protocol::Protocol::Http,
                                confidence: 80u8,
                                ..Default::default()
                            });
                        }
                    }
                } else {
                    // HTTP header不完整，累积数据
                    log::debug!("First segment: HTTP header incomplete, accumulating data (session: {})", session_id);
                    scanner.append_to_stream_buffer(session_id, payload)?;

                    // 更新会话状态，但不进行匹配
                    scanner.update_session_state(session_id, Some(crate::protocol::Protocol::Http), true, false, None);
                    log::debug!("First segment: session updated, waiting for more data (session: {})", session_id);

                    // 返回空结果，等待更多数据
                    return Ok(WebScanResult {
                        content_length: payload.len() as u32,
                        protocol: crate::protocol::Protocol::Http,  // 预设为HTTP，因为我们已经检测到HTTP模式
                        confidence: 80u8,  // 给一个合理的置信度
                        ..Default::default()
                    });
                }
            } else {
                // 后续分段
                log::debug!("Subsequent segment: checking candidate rules and HTTP header completion (session: {})", session_id);

                // 检查是否有候选规则
                let session_state = scanner.get_session_state(session_id);
                let (should_continue, _use_candidate_rules) = if let Some((_, _, _, ref candidate_rules)) = session_state {
                    if let Some(ref candidates) = candidate_rules {
                        if candidates.is_empty() {
                        // Fast pattern没有匹配，但仍然需要完整匹配（对于Fast pattern不在header中的规则）
                        log::debug!("Subsequent segment: no candidate rules from fast pattern, but proceeding with full matching for non-header fast pattern rules (session: {})", session_id);
                        (true, false)
                    } else {
                            log::debug!("Subsequent segment: using {} candidate rules from fast pattern (session: {})", candidates.len(), session_id);
                            (true, true)
                        }
                    } else {
                        // 没有候选规则信息，可能是没有Fast pattern数据库的情况
                        log::debug!("Subsequent segment: no candidate rules information, proceeding with full matching (session: {})", session_id);
                        (true, false)
                    }
                } else {
                    // 没有会话状态信息，可能是没有Fast pattern数据库的情况
                    log::debug!("Subsequent segment: no session state information, proceeding with full matching (session: {})", session_id);
                    (true, false)
                };

                if should_continue {
                    // 累积数据
                    scanner.append_to_stream_buffer(session_id, payload)?;
                    let accumulated = scanner.get_stream_buffer(session_id).unwrap_or_default();
                    log::debug!("Subsequent segment: accumulated {} bytes total (session: {})", accumulated.len(), session_id);

                    // 检查HTTP header是否完整
                    if crate::hyperscan::HyperscanScanner::is_http_header_complete(&accumulated) {
                        // HTTP header现在完整了
                        log::debug!("Subsequent segment: HTTP header now complete, proceeding with matching (session: {})", session_id);
                        scanner.set_http_header_complete(session_id, true);
                        scanner.update_session_state(session_id, Some(crate::protocol::Protocol::Http), true, true, session_state.and_then(|(_, _, _, rules)| rules));

                        // 使用累积的数据进行匹配
                        return self._hyperscan_match_with_session_and_result(session_id, &accumulated, is_final, reset_on_request_end, Some(crate::protocol::Protocol::Http));
                    } else {
                        // HTTP header仍然不完整
                        log::debug!("Subsequent segment: HTTP header still incomplete (session: {})", session_id);
                        scanner.update_session_state(session_id, Some(crate::protocol::Protocol::Http), true, false, session_state.and_then(|(_, _, _, rules)| rules));

                        // 返回空结果，等待更多数据
                        return Ok(WebScanResult {
                            content_length: payload.len() as u32,
                            protocol: crate::protocol::Protocol::Http,
                            confidence: 80u8,
                            ..Default::default()
                        });
                    }
                }
            }
        }

        // 没有Hyperscan扫描器或继续处理：使用原始payload
        let actual_payload = payload;

        // 第一步：协议检测
        // 分析数据包内容，判断是否为Web流量
        let protocol_result = self.protocol_detector.detect(actual_payload)?;

        // 记录协议统计
        self.stats.record_protocol(protocol_result.protocol);
        
        // 只处理Web流量（HTTP、HTTPS、HTTP/2）
        if !matches!(protocol_result.protocol, Protocol::Http | Protocol::Https | Protocol::Http2) {
            // 如果不是Web流量，返回结果但不进行内容检测
            // 注意：即使协议未知，也应该记录payload的实际长度
            return Ok(WebScanResult {
                protocol: protocol_result.protocol,
                confidence: protocol_result.confidence,
                content_length: payload.len() as u32,  // 记录实际payload长度
                ..Default::default()
            });
        }

        // 第二步：内容转换
        // 将字节数据转换为字符串，用于规则匹配
        let _content = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => {
                // 如果UTF-8转换失败，尝试提取可打印的ASCII字符
                let ascii_content: String = payload
                    .iter()
                    .filter(|&&b| b >= 32 && b <= 126)
                    .map(|&b| b as char)
                    .collect();
                
                if ascii_content.is_empty() {
                    return Ok(WebScanResult {
                        protocol: protocol_result.protocol,
                        confidence: protocol_result.confidence,
                        content_length: payload.len() as u32,  // 记录实际payload长度
                        ..Default::default()
                    });
                }
                
                Box::leak(ascii_content.into_boxed_str())
            }
        };

        // 第三步：规则匹配 - 使用 Hyperscan（带会话管理）
        let (matched_rule_id, action) = {
            // 使用 Hyperscan 进行高性能匹配（带会话管理，始终启用）
            match self._hyperscan_match_with_session(session_id, payload, is_final, reset_on_request_end) {
                Ok(Some(rule_id)) => {
                    // 从规则管理器获取完整的规则信息
                    let rule_manager = self.rule_manager.read();
                    if let Some(rule) = rule_manager.get_rule(rule_id) {
                        (Some(rule_id), Some(rule.action))
                    } else {
                        (Some(rule_id), None)
                    }
                }
                Ok(None) => (None, None),
                Err(e) => {
                    log::warn!("Hyperscan matching failed: {}", e);
                    (None, None)
                }
            }
        };

        // 注释：不再需要回退到regex匹配，Hyperscan始终启用
        // 保留此代码段以备需要时的PCRE fallback处理

        // 如果没有匹配的规则，返回"无匹配"结果
        if matched_rule_id.is_none() {
            return Ok(WebScanResult {
                protocol: protocol_result.protocol,
                confidence: protocol_result.confidence,
                content_length: payload.len() as u32,
                ..Default::default()
            });
        }

        // 更新统计信息：增加匹配的数据包计数
        self.stats.increment_packets_matched();

        // 获取匹配的规则ID和动作
        let rule_id = matched_rule_id.unwrap();

        // 确定要执行的动作
        let action = if let Some(rule_action) = action {
            if rule_action == RuleAction::None {
                self.default_action
            } else {
                rule_action.into()
            }
        } else {
            log::warn!("Hyperscan matched rule ID {} but rule not found in manager", rule_id);
            self.default_action
        };

        // 根据动作类型更新相应的统计信息
        match action {
            WebScanAction::Drop => self.stats.increment_packets_dropped(),
            WebScanAction::Reset => self.stats.increment_packets_reset(),
            _ => self.stats.increment_packets_alerted(),
        }

        // 构建并返回检测结果
        Ok(WebScanResult {
            is_matched: true,
            rule_id,
            action,
            content_length: payload.len() as u32,
            protocol: protocol_result.protocol,
            confidence: protocol_result.confidence,
        })
    }

    /// 重置指定会话的Hyperscan流
    ///
    /// 重置流的状态，使其可以重新开始匹配，但不关闭流。
    /// 这对于处理HTTP请求/响应流非常有用：当一个HTTP请求结束时，
    /// 可以重置流以准备处理下一个请求。
    ///
    /// # 参数
    /// * `session_id` - 要重置的会话标识符
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn reset_session(&self, session_id: u64) -> Result<()> {
        if let Some(ref scanner) = &self.hyperscan_scanner {
            scanner.reset_session(session_id)?;
        }
        Ok(())
    }

    /// 清理指定会话的Hyperscan流
    ///
    /// # 参数
    /// * `session_id` - 要清理的会话标识符
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn close_session(&self, session_id: u64) -> Result<()> {
        if let Some(ref scanner) = &self.hyperscan_scanner {
            scanner.close_session(session_id)?;
        }
        Ok(())
    }

    /// 清理所有会话的Hyperscan流
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn close_all_sessions(&self) -> Result<()> {
        if let Some(ref scanner) = &self.hyperscan_scanner {
            scanner.close_all_sessions()?;
        }
        Ok(())
    }

    /// 启用或禁用检测引擎
    /// 
    /// # 参数
    /// * `enabled` - 是否启用引擎
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// 检查引擎是否启用
    /// 
    /// # 返回值
    /// * `bool` - 如果启用返回true，否则返回false
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 设置默认动作
    /// 
    /// 当规则指定"无动作"时，引擎将使用这个默认动作。
    /// 
    /// # 参数
    /// * `action` - 新的默认动作
    pub fn set_default_action(&mut self, action: WebScanAction) {
        self.default_action = action;
    }

    /// 获取当前统计信息
    /// 
    /// # 返回值
    /// * `WebScanStats` - 当前的统计信息快照
    pub fn get_stats(&self) -> crate::stats::WebScanStats {
        self.stats.get_stats()
    }

    /// 重置统计信息
    /// 
    /// 将所有计数器重置为0，开始新的统计周期。
    pub fn reset_stats(&self) {
        self.stats.reset();
    }

    /// 获取规则统计信息
    /// 
    /// # 返回值
    /// * `u32` - 当前加载的规则总数
    pub fn get_rule_count(&self) -> u32 {
        let rule_manager = self.rule_manager.read();
        rule_manager.rule_count()
    }

    /// 重新加载规则
    ///
    /// 从指定路径重新加载规则文件，替换现有的所有规则。
    ///
    /// # 参数
    /// * `rules_path` - 新的规则文件路径
    ///
    /// # 返回值
    /// * `Result<u32>` - 成功返回加载的规则数量，失败返回错误
    pub fn reload_rules(&mut self, rules_path: &str) -> Result<u32> {
        // 获取规则管理器的写锁
        let count = {
            let mut rule_manager = self.rule_manager.write();
            
            // 清空现有规则
            rule_manager.clear_rules();
            
            // 加载新规则
            let count = rule_manager.load_rules_from_file(rules_path.as_ref())?;
            
            count
        };
        
        // 重新编译Hyperscan数据库（Hyperscan始终启用）
        let rule_manager = self.rule_manager.read();
        let rules: Vec<_> = rule_manager.get_all_rules().values().cloned().collect();
        drop(rule_manager); // 显式释放锁
        self._compile_hyperscan_database(&rules)?;
        
        // 记录重新加载的信息
        log::info!("Reloaded {} rules from {}", count, rules_path);
        
        Ok(count)
    }

    /// Hyperscan始终启用，此方法已移除
    ///
    /// 为了向后兼容性，提供此方法，但始终返回true
    #[deprecated(note = "Hyperscan is now always enabled")]
    pub fn is_hyperscan_enabled(&self) -> bool {
        true
    }
}

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    // 导入父模块的所有公共项
    use super::*;

    /// 测试引擎创建和基本功能
    #[test]
    fn test_engine_creation() {
        let engine = WebScanEngine::new();
        assert!(engine.is_enabled());
        assert_eq!(engine.get_rule_count(), 0);
    }

    /// 测试HTTP载荷处理
    #[test]
    fn test_http_payload_processing() {
        let engine = WebScanEngine::new();
        
        // 模拟HTTP请求载荷
        let http_payload = b"GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 处理载荷
        let result = engine.process_payload(http_payload).unwrap();
        
        // 验证结果
        assert_eq!(result.protocol, Protocol::Http);
        assert!(result.confidence > 0);
        assert_eq!(result.content_length, http_payload.len() as u32);
    }

    /// 测试引擎启用/禁用功能
    #[test]
    fn test_engine_enable_disable() {
        let mut engine = WebScanEngine::new();
        
        // 默认应该启用
        assert!(engine.is_enabled());
        
        // 禁用引擎
        engine.set_enabled(false);
        assert!(!engine.is_enabled());
        
        // 禁用状态下应该返回默认结果
        let result = engine.process_payload(b"GET / HTTP/1.1").unwrap();
        assert!(!result.is_matched);
    }

    /// 测试带会话的载荷处理
    #[test]
    fn test_process_payload_with_session() {
        let engine = WebScanEngine::new();
        
        let session_id = 30001;
        let http_payload = b"GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 处理载荷（带会话）
        let result = engine.process_payload_with_session(session_id, http_payload, false, false).unwrap();
        
        // 验证结果
        assert_eq!(result.protocol, Protocol::Http);
        assert!(result.confidence > 0);
        assert_eq!(result.content_length, http_payload.len() as u32);
    }

    /// 测试请求结束时重置
    #[test]
    fn test_reset_on_request_end() {
        let engine = WebScanEngine::new();
        
        let session_id = 30002;
        let request_payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 第一次请求
        let result1 = engine.process_payload_with_session(session_id, request_payload, false, true).unwrap();
        assert_eq!(result1.protocol, Protocol::Http);
        
        // 第二次请求（重置后应该可以正常处理）
        let result2 = engine.process_payload_with_session(session_id, request_payload, false, false).unwrap();
        assert_eq!(result2.protocol, Protocol::Http);
    }

    /// 测试会话重置功能
    #[test]
    fn test_engine_reset_session() {
        let engine = WebScanEngine::new();
        
        let session_id = 30003;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 处理载荷
        engine.process_payload_with_session(session_id, payload, false, false).unwrap();
        
        // 重置会话
        assert!(engine.reset_session(session_id).is_ok());
        
        // 重置后应该可以继续使用
        let result = engine.process_payload_with_session(session_id, payload, false, false).unwrap();
        assert_eq!(result.protocol, Protocol::Http);
    }

    /// 测试关闭会话
    #[test]
    fn test_engine_close_session() {
        let engine = WebScanEngine::new();
        
        let session_id = 30004;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 创建会话
        engine.process_payload_with_session(session_id, payload, false, false).unwrap();
        
        // 关闭会话
        assert!(engine.close_session(session_id).is_ok());
        
        // 关闭后重置应该成功（但会话不存在）
        assert!(engine.reset_session(session_id).is_ok());
    }

    /// 测试会话结束时自动关闭
    #[test]
    fn test_engine_session_final() {
        let engine = WebScanEngine::new();
        
        let session_id = 30005;
        let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // 处理载荷并标记为最终
        let result = engine.process_payload_with_session(session_id, payload, true, false).unwrap();
        assert_eq!(result.protocol, Protocol::Http);
        
        // 会话应该已经被关闭，再次使用应该创建新会话
        let result2 = engine.process_payload_with_session(session_id, payload, false, false).unwrap();
        assert_eq!(result2.protocol, Protocol::Http);
    }

    /// 测试多个会话并发处理
    #[test]
    fn test_engine_multiple_sessions() {
        let engine = WebScanEngine::new();
        
        // 创建多个不同的会话
        for i in 1..=3 {
            let session_id = 30010 + i;
            let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
            let result = engine.process_payload_with_session(session_id, payload, false, false).unwrap();
            assert_eq!(result.protocol, Protocol::Http);
        }
        
        // 验证所有会话都可以独立操作
        for i in 1..=3 {
            let session_id = 30010 + i;
            assert!(engine.reset_session(session_id).is_ok());
        }
        
        // 清理所有会话
        assert!(engine.close_all_sessions().is_ok());
    }
}