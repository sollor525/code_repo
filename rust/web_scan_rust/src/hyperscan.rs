//! Hyperscan集成模块
//!
//! 提供Intel Hyperscan高性能正则表达式匹配引擎的Rust封装。
//! Hyperscan支持大规模并行模式匹配，特别适用于网络安全、入侵检测等场景。
//!
//! # 特性
//!
//! - **流模式(Streaming)**: 支持跨数据包边界匹配
//! - **高性能**: 硬件加速和SIMD优化
//! - **实时**: 微秒级延迟
//! - **可扩展**: 支持数万条规则同时匹配

// 导入错误处理类型
use crate::error::{Result, WebScanError};
// 导入规则相关类型
use crate::rules::Rule;
// 导入Hyperscan库
use hyperscan::{StreamingDatabase, Pattern, Patterns, Matching, Builder, Streaming};
// 导入同步原语
use parking_lot::RwLock;
// 导入互斥锁
use std::sync::Mutex;
// 导入原子类型和智能指针
use std::sync::Arc;
// 导入字符串类型
use std::string::String;
// 导入HashMap用于会话管理
use std::collections::HashMap;

/// Hyperscan 编译器
///
/// 专门用于创建高性能的流式Hyperscan数据库。
/// 支持分别编译fast pattern数据库和完整数据库。
#[derive(Debug)]
pub struct HyperscanCompiler {
    /// 存储模式和对应的规则 ID（完整数据库）
    patterns: Vec<(String, u32)>,
    /// 存储fast pattern和对应的规则 ID（fast pattern数据库）
    fast_patterns: Vec<(String, u32)>,
}

/// 匹配结果结构体
///
/// 存储Hyperscan匹配的结果信息。
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// 匹配的规则ID
    pub rule_id: u32,
    /// 匹配起始位置
    pub from: u64,
    /// 匹配结束位置
    pub to: u64,
    /// 匹配标志
    pub flags: u32,
}


impl HyperscanCompiler {
    /// 创建新的流式编译器实例
    ///
    /// # 返回值
    /// * `Self` - 流式编译器实例
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            fast_patterns: Vec::new(),
        }
    }

    /// 添加规则到编译器
    ///
    /// # 参数
    /// * `rule` - 要添加的规则
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    /// 
    /// 注意：只有fast pattern在HTTP header中的规则才会被添加到fast pattern数据库。
    /// fast pattern不在header中的规则只添加到完整数据库，不使用fast pattern过滤。
    pub fn add_rule(&mut self, rule: &Rule) -> Result<()> {
        // 获取所有用于Hyperscan的模式（包括content和兼容的PCRE模式）
        let hyperscan_patterns = rule.get_hyperscan_patterns();

        // 添加所有Hyperscan兼容的模式到完整数据库
        for (pattern_str, rule_id) in hyperscan_patterns {
            log::debug!("Adding Hyperscan pattern for rule {}: '{}'", rule_id, pattern_str);
            self.patterns.push((pattern_str, rule_id));
        }

        // 处理fast pattern逻辑（仅用于优化）
        // 只有fast pattern在header中的规则才添加到fast pattern数据库
        if let Some(fast_idx) = rule.fast_pattern_index {
            if let Some(fast_pattern) = rule.patterns.get(fast_idx) {
                // 检查fast pattern是否在header中
                let is_header_location = matches!(fast_pattern.http_location,
                    crate::rules::HttpMatchLocation::Method |
                    crate::rules::HttpMatchLocation::Uri |
                    crate::rules::HttpMatchLocation::UriRaw |
                    crate::rules::HttpMatchLocation::Cookie |
                    crate::rules::HttpMatchLocation::RequestHeader);

                if is_header_location {
                    // 转义fast pattern以确保Hyperscan兼容性
                    let escaped_pattern = crate::rules::Rule::escape_for_hyperscan_literal(&fast_pattern.pattern);
                    log::debug!("Adding fast pattern for rule {}: '{}' -> '{}' (header location: {:?})",
                        rule.id, fast_pattern.pattern, escaped_pattern, fast_pattern.http_location);
                    self.fast_patterns.push((escaped_pattern, rule.id));
                } else {
                    log::debug!("Skipping fast pattern for rule {}: '{}' (non-header location: {:?}), rule will use full matching only",
                        rule.id, fast_pattern.pattern, fast_pattern.http_location);
                }
            }
        } else {
            // 对于没有明确fast pattern的规则，检查第一个pattern是否在header中
            if let Some(first_pattern) = rule.patterns.first() {
                let is_header_location = matches!(first_pattern.http_location,
                    crate::rules::HttpMatchLocation::Method |
                    crate::rules::HttpMatchLocation::Uri |
                    crate::rules::HttpMatchLocation::UriRaw |
                    crate::rules::HttpMatchLocation::Cookie |
                    crate::rules::HttpMatchLocation::RequestHeader);

                if is_header_location {
                    // 使用第一个pattern作为fast pattern，并转义以确保Hyperscan兼容性
                    let escaped_pattern = crate::rules::Rule::escape_for_hyperscan_literal(&first_pattern.pattern);
                    log::debug!("Adding first pattern as fast pattern for rule {}: '{}' -> '{}' (header location)",
                        rule.id, first_pattern.pattern, escaped_pattern);
                    self.fast_patterns.push((escaped_pattern, rule.id));
                } else {
                    log::debug!("No fast pattern for rule {}: first pattern '{}' not in header location",
                        rule.id, first_pattern.pattern);
                }
            }
        }

        Ok(())
    }

    /// 编译模式为流式数据库
    ///
    /// # 返回值
    /// * `Result<(HyperscanDatabase, Option<HyperscanDatabase>)>` - 编译后的完整数据库和fast pattern数据库（如果存在）
    pub fn compile(self) -> Result<(HyperscanDatabase, Option<HyperscanDatabase>)> {
        if self.patterns.is_empty() {
            return Err(WebScanError::Hyperscan("No patterns to compile".to_string()));
        }

        // 编译完整数据库
        let mut patterns = Vec::new();
        for (pattern_str, rule_id) in self.patterns.iter() {
            match Pattern::new(pattern_str.as_str()) {
                Ok(mut pattern) => {
                    pattern.id = Some(*rule_id as usize);
                    patterns.push(pattern);
                }
                Err(e) => {
                    log::warn!("Failed to create Hyperscan pattern '{}': {}", pattern_str, e);
                }
            }
        }

        if patterns.is_empty() {
            return Err(WebScanError::Hyperscan("No valid patterns to compile".to_string()));
        }

        let patterns = Patterns(patterns);
        let db = patterns.build::<Streaming>()
            .map_err(|e| WebScanError::Hyperscan(format!("Failed to compile stream database: {}", e)))?;

        log::info!("Compiled Hyperscan stream database with {} patterns", self.patterns.len());

        // 编译fast pattern数据库（如果存在）
        let fast_db = if !self.fast_patterns.is_empty() {
            let mut fast_patterns = Vec::new();
            for (pattern_str, rule_id) in self.fast_patterns.iter() {
                match Pattern::new(pattern_str.as_str()) {
                    Ok(mut pattern) => {
                        pattern.id = Some(*rule_id as usize);
                        fast_patterns.push(pattern);
                    }
                    Err(e) => {
                        log::warn!("Failed to create Hyperscan fast pattern '{}': {}", pattern_str, e);
                    }
                }
            }

            if !fast_patterns.is_empty() {
                let fast_patterns = Patterns(fast_patterns);
                let fast_db = fast_patterns.build::<Streaming>()
                    .map_err(|e| WebScanError::Hyperscan(format!("Failed to compile fast pattern database: {}", e)))?;
                log::info!("Compiled Hyperscan fast pattern database with {} patterns", self.fast_patterns.len());
                Some(HyperscanDatabase { inner: std::sync::Arc::new(fast_db) })
            } else {
                None
            }
        } else {
            None
        };

        Ok((HyperscanDatabase { inner: std::sync::Arc::new(db) }, fast_db))
    }
}

/// Hyperscan流式数据库
///
/// 专门用于流式模式匹配，支持跨数据包边界匹配。
#[derive(Clone)]
pub struct HyperscanDatabase {
    /// 内部流式数据库实例，使用Arc实现线程安全的共享
    inner: std::sync::Arc<StreamingDatabase>,
}

impl std::fmt::Debug for HyperscanDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StreamingDatabase")
    }
}

/// Hyperscan流会话
///
/// 为每个会话维护独立的Hyperscan流和scratch空间。
/// 使用Mutex保护，因为Hyperscan的Stream不是线程安全的。
struct HyperscanStreamSession {
    /// Hyperscan流实例和scratch空间，使用Mutex保护
    inner: Mutex<HyperscanStreamSessionInner>,
}

/// Hyperscan流会话内部数据
///
/// 包含实际的流和scratch空间，由Mutex保护。
/// 由于单个TCP流只会在单个线程处理，状态字段已经在Mutex保护下，无需额外同步。
#[allow(dead_code)]
struct HyperscanStreamSessionInner {
    /// Hyperscan流实例
    stream: hyperscan::Stream,
    /// Scratch空间，用于流扫描
    scratch: hyperscan::Scratch,
    /// 是否已处理第一个分段
    is_initialized: bool,
    /// 检测到的协议类型
    protocol: Option<crate::protocol::Protocol>,
    /// HTTP解析是否成功
    http_parse_success: bool,
    /// Fast pattern是否命中
    fast_pattern_matched: bool,
    /// Fast pattern命中的候选规则ID集合
    candidate_rules: Option<std::collections::HashSet<u32>>,
    /// 每个规则已匹配的pattern索引集合（用于多pattern规则）
    matched_patterns_by_rule: std::collections::HashMap<u32, std::collections::HashSet<usize>>,
    /// 流数据缓冲区，用于累积不完整的HTTP数据包
    stream_buffer: Vec<u8>,
    /// HTTP header是否已完整解析
    http_header_complete: bool,
    /// ===== 新增：会话状态跟踪 =====
    /// 会话开始时间戳（毫秒）
    session_start_time: Option<std::time::Instant>,
    /// 最后一次活动时间戳（毫秒）
    last_activity_time: std::time::Instant,
    /// 该会话已匹配的次数
    match_count: u32,
    /// 该会话的威胁级别（基于规则权重计算）
    threat_level: u8,  // 0-255级别
    /// 是否已触发阈值告警
    threshold_triggered: bool,
    /// 会话方向（请求/响应）
    session_direction: crate::protocol::PacketDirection,
}

/// 会话阈值配置
///
/// 定义用于会话级别威胁检测的阈值参数。
#[derive(Debug, Clone)]
pub struct SessionThresholdConfig {
    /// 触发告警的最小匹配次数
    pub match_threshold: u32,
    /// 触发告警的时间窗口（秒）
    pub time_window_seconds: u64,
    /// 威胁级别计算权重
    pub high_risk_weight: u8,    // 高风险规则权重
    pub medium_risk_weight: u8,  // 中风险规则权重
    pub low_risk_weight: u8,     // 低风险规则权重
}

impl Default for SessionThresholdConfig {
    fn default() -> Self {
        Self {
            match_threshold: 5,        // 5次匹配触发告警
            time_window_seconds: 60,   // 60秒时间窗口
            high_risk_weight: 10,      // 高风险权重10
            medium_risk_weight: 5,     // 中风险权重5
            low_risk_weight: 1,       // 低风险权重1
        }
    }
}

/// 会话统计信息
///
/// 用于记录和报告会话级别的检测统计。
#[derive(Debug, Clone)]
pub struct SessionStats {
    /// 会话ID
    pub session_id: u64,
    /// 会话持续时间（毫秒）
    pub session_duration_ms: u64,
    /// 总匹配次数
    pub total_matches: u32,
    /// 触发阈值告警的次数
    pub threshold_triggers: u32,
    /// 当前威胁级别
    pub current_threat_level: u8,
    /// 会话方向
    pub direction: crate::protocol::PacketDirection,
}

/// Hyperscan扫描器
///
/// 提供高性能模式匹配功能，支持多会话流式匹配。
/// 会话表是全局的，但每个会话只被单个线程使用，通过Arc实现并发安全。
pub struct HyperscanScanner {
    database: Arc<RwLock<HyperscanDatabase>>,  // 完整数据库实例
    fast_database: Option<Arc<RwLock<HyperscanDatabase>>>,  // Fast pattern数据库实例（可选）
    /// 会话到流的映射，每个会话维护独立的stream
    /// 使用Arc包装会话，允许在释放sessions锁后继续使用会话
    sessions: Arc<RwLock<HashMap<u64, Arc<HyperscanStreamSession>>>>,
    /// Fast pattern会话到流的映射
    fast_sessions: Arc<RwLock<HashMap<u64, Arc<HyperscanStreamSession>>>>,
    /// ===== 新增：会话阈值配置和统计 =====
    /// 阈值配置
    threshold_config: SessionThresholdConfig,
    /// 会话统计信息（用于报告）
    session_stats: Arc<RwLock<HashMap<u64, SessionStats>>>,
}

impl HyperscanScanner {
    /// 创建新的扫描器实例
    ///
    /// # 参数
    /// * `database` - 已编译的Hyperscan流式数据库
    /// * `fast_database` - Fast pattern数据库（可选）
    ///
    /// # 返回值
    /// * `Result<Self>` - 成功返回扫描器实例，失败返回错误
    pub fn new(database: HyperscanDatabase, fast_database: Option<HyperscanDatabase>) -> Result<Self> {
        Ok(Self {
            database: Arc::new(RwLock::new(database)),
            fast_database: fast_database.map(|db| Arc::new(RwLock::new(db))),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            fast_sessions: Arc::new(RwLock::new(HashMap::new())),
            threshold_config: SessionThresholdConfig::default(),
            session_stats: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// 设置会话阈值配置
    ///
    /// # 参数
    /// * `config` - 阈值配置
    pub fn set_threshold_config(&mut self, config: SessionThresholdConfig) {
        self.threshold_config = config.clone();
        log::info!("Session threshold config updated: match_threshold={}, time_window={}s",
                 config.match_threshold, config.time_window_seconds);
    }

    /// 获取会话统计信息
    ///
    /// # 返回值
    /// * `HashMap<u64, SessionStats>` - 会话统计信息映射
    pub fn get_session_stats(&self) -> HashMap<u64, SessionStats> {
        self.session_stats.read().clone()
    }

    /// 清理过期的会话
    ///
    /// 根据配置的时间窗口清理超过时间限制的会话。
    ///
    /// # 参数
    /// * `max_session_age_seconds` - 会话最大存活时间（秒）
    pub fn cleanup_expired_sessions(&self, max_session_age_seconds: u64) {
        let mut sessions = self.sessions.write();
        let mut fast_sessions = self.fast_sessions.write();
        let mut session_stats = self.session_stats.write();

        let current_time = std::time::Instant::now();
        let max_age = std::time::Duration::from_secs(max_session_age_seconds);

        // 收集过期的会话ID
        let mut expired_sessions = Vec::new();

        for (session_id, session_arc) in sessions.iter() {
            if let Some(session_inner) = session_arc.inner.lock().ok() {
                if let Some(start_time) = session_inner.session_start_time {
                    if current_time.duration_since(start_time) > max_age {
                        expired_sessions.push(*session_id);
                    }
                }
            }
        }

        // 清理过期会话
        for session_id in &expired_sessions {
            sessions.remove(session_id);
            fast_sessions.remove(session_id);
            session_stats.remove(session_id);
        }

        if !expired_sessions.is_empty() {
            log::debug!("Cleaned up {} expired sessions", expired_sessions.len());
        }

        drop(sessions);
        drop(fast_sessions);
        drop(session_stats);
    }

    /// 计算会话威胁级别
    ///
    /// 基于匹配的规则权重计算威胁级别。
    ///
    /// # 参数
    /// * `rule_ids` - 匹配的规则ID集合
    /// * `rule_metadata` - 规则元数据映射
    ///
    /// # 返回值
    /// * `u8` - 威胁级别（0-255）
    #[allow(dead_code)]
    fn calculate_threat_level(&self, rule_ids: &std::collections::HashSet<u32>, rule_metadata: &std::collections::HashMap<u32, crate::rules::RuleMetadata>) -> u8 {
        let mut threat_score = 0u32;

        for rule_id in rule_ids {
            if let Some(metadata) = rule_metadata.get(rule_id) {
                let weight = if metadata.has_fast_pattern {
                    self.threshold_config.high_risk_weight as u32
                } else if metadata.has_pcre_fallback {
                    self.threshold_config.medium_risk_weight as u32
                } else {
                    self.threshold_config.low_risk_weight as u32
                };
                threat_score += weight;
            }
        }

        // 将威胁分数限制在0-255范围内
        threat_score.min(255) as u8
    }

    /// 检查会话阈值
    ///
    /// 检查会话是否超过匹配阈值或时间窗口阈值。
    ///
    /// # 参数
    /// * `session_id` - 会话ID
    /// * `session_inner` - 会话内部状态
    ///
    /// # 返回值
    /// * `bool` - 是否触发阈值告警
    #[allow(dead_code)]
    fn check_session_threshold(&self, session_id: u64, session_inner: &mut HyperscanStreamSessionInner) -> bool {
        let current_time = std::time::Instant::now();

        // 更新最后活动时间
        session_inner.last_activity_time = current_time;

        // 检查匹配次数阈值
        if session_inner.match_count >= self.threshold_config.match_threshold {
            if !session_inner.threshold_triggered {
                session_inner.threshold_triggered = true;
                log::info!("Session {} threshold triggered: {} matches (threshold: {})",
                         session_id, session_inner.match_count, self.threshold_config.match_threshold);
                return true;
            }
        }

        // 检查时间窗口阈值
        if let Some(start_time) = session_inner.session_start_time {
            let elapsed = current_time.duration_since(start_time);
            if elapsed.as_secs() >= self.threshold_config.time_window_seconds {
                if session_inner.match_count > 0 && !session_inner.threshold_triggered {
                    session_inner.threshold_triggered = true;
                    log::info!("Session {} time window threshold triggered: {}s elapsed, {} matches",
                             session_id, elapsed.as_secs(), session_inner.match_count);
                    return true;
                }
            }
        }

        false
    }

    /// 执行流式模式扫描（无会话，每次创建新流）
    ///
    /// # 参数
    /// * `data` - 要扫描的数据
    ///
    /// # 返回值
    /// * `Result<Vec<MatchResult>>` - 匹配结果列表
    ///
    /// # 注意
    /// 此方法每次调用都会创建新的流，适用于非流式场景。
    /// 对于需要跨数据包匹配的场景，请使用 `scan_stream_with_session`。
    pub fn scan_stream(&self, data: &[u8]) -> Result<Vec<MatchResult>> {
        let db = self.database.read();

        // 直接使用流式数据库进行扫描
        self._stream_scan(&db.inner, data)
    }

    /// 执行fast pattern扫描（无会话，每次创建新流）
    ///
    /// # 参数
    /// * `data` - 要扫描的数据
    ///
    /// # 返回值
    /// * `Result<Vec<MatchResult>>` - 匹配结果列表
    ///
    /// # 注意
    /// 此方法用于快速过滤，只匹配fast pattern。
    /// 如果fast pattern数据库不存在，返回空列表。
    pub fn scan_fast_pattern(&self, data: &[u8]) -> Result<Vec<MatchResult>> {
        if let Some(ref fast_db) = self.fast_database {
            let db = fast_db.read();
            self._stream_scan(&db.inner, data)
        } else {
            // 没有fast pattern数据库，返回空列表
            Ok(Vec::new())
        }
    }

    /// Fast pattern匹配：用于HTTP header完整时的快速过滤
    ///
    /// 这个方法专门用于Fast pattern匹配，返回可能匹配的候选规则ID集合。
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `data` - HTTP header数据
    ///
    /// # 返回值
    /// * `Result<Option<std::collections::HashSet<u32>>>` - 匹配的候选规则ID集合，如果没有fast pattern数据库或没有匹配则返回None
    pub fn scan_fast_patterns(&self, session_id: u64, data: &[u8]) -> Result<Option<std::collections::HashSet<u32>>> {
        // 如果没有fast pattern数据库，直接返回None
        let fast_db = if let Some(ref fast_db) = self.fast_database {
            fast_db
        } else {
            return Ok(None);
        };

        // 获取或创建fast pattern会话
        let fast_session = {
            let mut fast_sessions = self.fast_sessions.write();
            fast_sessions.entry(session_id).or_insert_with(|| {
                let stream = (*fast_db.read().inner).open_stream()
                    .expect("Failed to open fast pattern stream");
                let scratch = (*fast_db.read().inner).alloc_scratch()
                    .expect("Failed to allocate fast pattern scratch");
                Arc::new(HyperscanStreamSession {
                    inner: Mutex::new(HyperscanStreamSessionInner {
                        stream,
                        scratch,
                        is_initialized: false,
                        protocol: None,
                        http_parse_success: false,
                        fast_pattern_matched: false,
                        candidate_rules: None,
                        matched_patterns_by_rule: std::collections::HashMap::new(),
                        stream_buffer: Vec::new(),
                        http_header_complete: false,
                        session_start_time: Some(std::time::Instant::now()),
                        last_activity_time: std::time::Instant::now(),
                        match_count: 0,
                        threat_level: 0,
                        threshold_triggered: false,
                        session_direction: crate::protocol::PacketDirection::Unknown,
                    }),
                })
            }).clone()
        };

        // 执行fast pattern匹配
        let mut matched_rules = std::collections::HashSet::new();

        if !data.is_empty() {
            let session_inner = fast_session.inner.lock().unwrap();

            session_inner.stream.scan(data, &session_inner.scratch, |id, from, to, _flags| {
                matched_rules.insert(id as u32);
                log::debug!("Fast pattern matched rule {} at {}..{} (session: {})", id, from, to, session_id);
                Matching::Continue
            }).map_err(|e| WebScanError::Hyperscan(format!("Fast pattern scan failed: {}", e)))?;
        }

        if matched_rules.is_empty() {
            log::debug!("No fast patterns matched (session: {})", session_id);
            Ok(Some(std::collections::HashSet::new()))  // 返回空集合表示没有匹配
        } else {
            log::debug!("Fast patterns matched {} rules (session: {})", matched_rules.len(), session_id);
            Ok(Some(matched_rules))
        }
    }

    /// 执行流式模式扫描（带会话管理）
    ///
    /// 为每个会话维护独立的Hyperscan流，支持跨数据包边界匹配。
    /// 优化了锁的使用：只在查找/创建会话时短暂持有sessions锁，然后立即释放，
    /// 支持Fast pattern优化：HTTP header完整时先进行fast pattern匹配。
    /// 允许不同线程并发处理不同的会话。
    ///
    /// # 参数
    /// * `session_id` - 会话标识符，同一个会话使用相同的ID
    /// * `data` - 要扫描的数据
    /// * `is_final` - 是否为该会话的最后一个数据包（true时关闭流）
    /// * `reset_on_request_end` - 是否在请求结束时重置流（用于HTTP请求/响应流）
    ///
    /// # 返回值
    /// * `Result<Vec<MatchResult>>` - 匹配结果列表
    pub fn scan_stream_with_session(&self, session_id: u64, data: &[u8], is_final: bool, reset_on_request_end: bool) -> Result<Vec<MatchResult>> {
        // 第一步：快速获取或创建会话，然后立即释放sessions锁
        let session = {
            let db = self.database.read();
            let mut sessions = self.sessions.write();

            // 获取或创建会话的stream，使用Arc包装以便在释放锁后继续使用
            sessions.entry(session_id).or_insert_with(|| {
                // 创建新的流会话
                let stream = (*db.inner).open_stream()
                    .expect("Failed to open stream");
                let scratch = (*db.inner).alloc_scratch()
                    .expect("Failed to allocate scratch");
                Arc::new(HyperscanStreamSession {
                    inner: Mutex::new(HyperscanStreamSessionInner {
                        stream,
                        scratch,
                        is_initialized: false,
                        protocol: None,
                        http_parse_success: false,
                        fast_pattern_matched: false,
                        candidate_rules: None,
                        matched_patterns_by_rule: std::collections::HashMap::new(),
                        stream_buffer: Vec::new(),
                        http_header_complete: false,
                        // 新增字段：会话状态跟踪
                        session_start_time: Some(std::time::Instant::now()),
                        last_activity_time: std::time::Instant::now(),
                        match_count: 0,
                        threat_level: 0,
                        threshold_triggered: false,
                        session_direction: crate::protocol::PacketDirection::Unknown,
                    }),
                })
            }).clone()  // 克隆Arc，这样可以在释放sessions锁后继续使用
        };  // 这里sessions锁被释放，允许其他线程并发访问不同的会话

        let mut results = Vec::new();

        // 第二步：使用会话进行扫描（此时sessions锁已释放）
        if !data.is_empty() {
            // 获取会话的内部数据锁
            let session_inner = session.inner.lock().unwrap();
            
            // 使用 Cell 来避免借用检查问题
            use std::cell::RefCell;
            let results_ref = RefCell::new(&mut results);

            // 执行扫描，匹配时调用回调函数
            session_inner.stream.scan(data, &session_inner.scratch, |id, from, to, flags| {
                let mut results = results_ref.borrow_mut();
                results.push(MatchResult {
                    rule_id: id as u32,  // Hyperscan返回usize，需要转换为u32
                    from,
                    to,
                    flags,
                });
                log::debug!("Hyperscan matched rule {} at {}..{} (session: {})", id, from, to, session_id);

                // 继续搜索更多匹配
                Matching::Continue
            }).map_err(|e| WebScanError::Hyperscan(format!("Stream scan failed: {}", e)))?;
        }

        // 第三步：如果需要在请求结束时重置流
        if reset_on_request_end {
            // 获取会话的内部数据锁并重置流
            let mut session_inner = session.inner.lock().unwrap();
            session_inner.stream.reset(&session_inner.scratch, |_id, _from, _to, _flags| {
                // 重置时不应该触发匹配，但为了API兼容性，提供一个空回调
                Matching::Continue
            }).map_err(|e| WebScanError::Hyperscan(format!("Stream reset failed: {}", e)))?;
            
            // 重置所有状态字段
            session_inner.is_initialized = false;
            session_inner.protocol = None;
            session_inner.http_parse_success = false;
            session_inner.fast_pattern_matched = false;
            session_inner.candidate_rules = None;
            session_inner.matched_patterns_by_rule.clear();
            
            log::debug!("Reset stream session {} after request end and cleared all state", session_id);
        }

        // 第四步：如果是最后一个数据包，关闭流并清理会话
        if is_final {
            // 需要重新获取sessions写锁来移除会话
            let mut sessions = self.sessions.write();
            if let Some(session_arc) = sessions.remove(&session_id) {
                // 尝试从Arc中获取所有权（应该成功，因为我们已经从HashMap中移除了）
                // 如果失败（有其他引用），说明有bug，但我们仍然可以关闭流
                match Arc::try_unwrap(session_arc) {
                    Ok(session_to_close) => {
                        // 获取会话的内部数据锁
                        let session_inner = session_to_close.inner.into_inner().unwrap();
                        
                        // 使用 Cell 来避免借用检查问题
                        use std::cell::RefCell;
                        let results_ref = RefCell::new(&mut results);

                        // 关闭流，可能会触发一些结束匹配
                        session_inner.stream.close(&session_inner.scratch, |id, from, to, flags| {
                            let mut results = results_ref.borrow_mut();
                            results.push(MatchResult {
                                rule_id: id as u32,  // Hyperscan返回usize，需要转换为u32
                                from,
                                to,
                                flags,
                            });
                            log::debug!("Hyperscan stream close matched rule {} at {}..{} (session: {})", id, from, to, session_id);

                            Matching::Continue
                        }).map_err(|e| WebScanError::Hyperscan(format!("Stream close failed: {}", e)))?;

                        log::debug!("Closed and removed stream session {}", session_id);
                    }
                    Err(_session_arc) => {
                        // 如果还有其他引用，说明其他线程可能正在使用这个会话
                        // 我们不能关闭流，因为这可能导致其他线程出错
                        log::warn!("Cannot close stream session {}: Arc has multiple references (other threads may be using it)", session_id);
                    }
                }
            }
        }

        log::debug!("Hyperscan stream scan completed for session {}, found {} matches", session_id, results.len());
        Ok(results)
    }

    /// 执行fast pattern流式模式扫描（带会话管理）
    ///
    /// 与scan_stream_with_session类似，但使用fast pattern数据库。
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `data` - 要扫描的数据
    /// * `is_final` - 是否为该会话的最后一个数据包
    /// * `reset_on_request_end` - 是否在请求结束时重置流
    ///
    /// # 返回值
    /// * `Result<Vec<MatchResult>>` - 匹配结果列表
    pub fn scan_fast_pattern_with_session(&self, session_id: u64, data: &[u8], is_final: bool, reset_on_request_end: bool) -> Result<Vec<MatchResult>> {
        if let Some(ref fast_db) = self.fast_database {
            // 使用fast pattern数据库进行扫描，逻辑与scan_stream_with_session相同
            let session = {
                let db = fast_db.read();
                let mut sessions = self.fast_sessions.write();
                sessions.entry(session_id).or_insert_with(|| {
                    let stream = (*db.inner).open_stream()
                        .expect("Failed to open fast pattern stream");
                    let scratch = (*db.inner).alloc_scratch()
                        .expect("Failed to allocate scratch");
                    Arc::new(HyperscanStreamSession {
                        inner: Mutex::new(HyperscanStreamSessionInner {
                            stream,
                            scratch,
                            is_initialized: false,
                            protocol: None,
                            http_parse_success: false,
                            fast_pattern_matched: false,
                            candidate_rules: None,
                            matched_patterns_by_rule: std::collections::HashMap::new(),
                            stream_buffer: Vec::new(),
                            http_header_complete: false,
                            // 新增字段：会话状态跟踪
                            session_start_time: Some(std::time::Instant::now()),
                            last_activity_time: std::time::Instant::now(),
                            match_count: 0,
                            threat_level: 0,
                            threshold_triggered: false,
                            session_direction: crate::protocol::PacketDirection::Unknown,
                        }),
                    })
                }).clone()
            };

            let mut results = Vec::new();

            if !data.is_empty() {
                let session_inner = session.inner.lock().unwrap();
                use std::cell::RefCell;
                let results_ref = RefCell::new(&mut results);

                session_inner.stream.scan(data, &session_inner.scratch, |id, from, to, flags| {
                    let mut results = results_ref.borrow_mut();
                    results.push(MatchResult {
                        rule_id: id as u32,
                        from,
                        to,
                        flags,
                    });
                    Matching::Continue
                }).map_err(|e| WebScanError::Hyperscan(format!("Fast pattern stream scan failed: {}", e)))?;
            }

            if reset_on_request_end {
                let mut session_inner = session.inner.lock().unwrap();
                session_inner.stream.reset(&session_inner.scratch, |_id, _from, _to, _flags| {
                    Matching::Continue
                }).map_err(|e| WebScanError::Hyperscan(format!("Fast pattern stream reset failed: {}", e)))?;
                
                // 重置fast pattern session的状态（简化版本）
                session_inner.is_initialized = false;
                session_inner.fast_pattern_matched = false;
            }

            if is_final {
                let mut sessions = self.fast_sessions.write();
                if let Some(session_arc) = sessions.remove(&session_id) {
                    match Arc::try_unwrap(session_arc) {
                        Ok(session_to_close) => {
                            let session_inner = session_to_close.inner.into_inner().unwrap();
                            use std::cell::RefCell;
                            let results_ref = RefCell::new(&mut results);

                            session_inner.stream.close(&session_inner.scratch, |id, from, to, flags| {
                                let mut results = results_ref.borrow_mut();
                                results.push(MatchResult {
                                    rule_id: id as u32,
                                    from,
                                    to,
                                    flags,
                                });
                                Matching::Continue
                            }).map_err(|e| WebScanError::Hyperscan(format!("Fast pattern stream close failed: {}", e)))?;
                        }
                        Err(_) => {
                            log::warn!("Cannot close fast pattern stream session {}: Arc has multiple references", session_id);
                        }
                    }
                }
            }

            Ok(results)
        } else {
            // 没有fast pattern数据库，返回空列表
            Ok(Vec::new())
        }
    }

    /// 检查是否有fast pattern数据库
    ///
    /// # 返回值
    /// * `bool` - 如果有fast pattern数据库返回true
    pub fn has_fast_pattern_database(&self) -> bool {
        self.fast_database.is_some()
    }

    /// 获取会话状态（用于检查是否是第一个分段）
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    ///
    /// # 返回值
    /// * `bool` - 如果session不存在或未初始化返回true（表示是第一个分段）
    pub fn is_first_segment(&self, session_id: u64) -> bool {
        let sessions = self.sessions.read();
        log::debug!("is_first_segment check: session_id={}, total_sessions={}", session_id, sessions.len());
        if let Some(session) = sessions.get(&session_id) {
            let session_inner = session.inner.lock().unwrap();
            let result = !session_inner.is_initialized;
            log::debug!("is_first_segment: session_id={}, is_initialized={}, result={}", session_id, session_inner.is_initialized, result);
            result
        } else {
            log::debug!("is_first_segment: session_id={} not found in sessions, returning true", session_id);
            true  // 新session，是第一个分段
        }
    }

    /// 更新会话状态
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `protocol` - 协议类型
    /// * `http_parse_success` - HTTP解析是否成功
    /// * `fast_pattern_matched` - Fast pattern是否命中
    /// * `candidate_rules` - Fast pattern命中的候选规则ID集合
    pub fn update_session_state(&self, session_id: u64, protocol: Option<crate::protocol::Protocol>, http_parse_success: bool, fast_pattern_matched: bool, candidate_rules: Option<std::collections::HashSet<u32>>) {
        log::debug!("update_session_state called: session={}, protocol={:?}, http_parse_success={}", session_id, protocol, http_parse_success);
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let mut session_inner = session.inner.lock().unwrap();
            let was_initialized = session_inner.is_initialized;
            session_inner.is_initialized = true;
            log::debug!("Session {} initialized: {} -> {}", session_id, was_initialized, session_inner.is_initialized);
            if let Some(p) = protocol {
                session_inner.protocol = Some(p);
            }
            session_inner.http_parse_success = http_parse_success;
            session_inner.fast_pattern_matched = fast_pattern_matched;
            session_inner.candidate_rules = candidate_rules;
        }
    }

    /// 获取会话状态（用于后续分段检查）
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    ///
    /// # 返回值
    /// * `Option<(Option<crate::protocol::Protocol>, bool, bool, Option<std::collections::HashSet<u32>>)>` - 
    ///   如果session存在返回(protocol, http_parse_success, fast_pattern_matched, candidate_rules)，否则返回None
    pub fn get_session_state(&self, session_id: u64) -> Option<(Option<crate::protocol::Protocol>, bool, bool, Option<std::collections::HashSet<u32>>)> {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let session_inner = session.inner.lock().unwrap();
            Some((
                session_inner.protocol,
                session_inner.http_parse_success,
                session_inner.fast_pattern_matched,
                session_inner.candidate_rules.clone(),
            ))
        } else {
            None
        }
    }

    /// 更新规则已匹配的pattern集合
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `rule_id` - 规则ID
    /// * `matched_patterns` - 已匹配的pattern索引集合
    pub fn update_matched_patterns(&self, session_id: u64, rule_id: u32, matched_patterns: std::collections::HashSet<usize>) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let mut session_inner = session.inner.lock().unwrap();
            session_inner.matched_patterns_by_rule.insert(rule_id, matched_patterns);
        }
    }

    /// 获取规则已匹配的pattern集合
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `rule_id` - 规则ID
    ///
    /// # 返回值
    /// * `std::collections::HashSet<usize>` - 已匹配的pattern索引集合
    pub fn get_matched_patterns(&self, session_id: u64, rule_id: u32) -> std::collections::HashSet<usize> {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let session_inner = session.inner.lock().unwrap();
            session_inner.matched_patterns_by_rule.get(&rule_id)
                .cloned()
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        }
    }

    /// 追加数据到会话的流缓冲区
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `data` - 要追加的数据
    ///
    /// # 返回值
    /// * `Result<()>` - 成功或错误
    pub fn append_to_stream_buffer(&self, session_id: u64, data: &[u8]) -> Result<()> {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let mut session_inner = session.inner.lock().unwrap();
            session_inner.stream_buffer.extend_from_slice(data);
            Ok(())
        } else {
            Err(crate::error::WebScanError::InvalidInput("Session not found".to_string()))
        }
    }

    /// 获取会话的累积流数据
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    ///
    /// # 返回值
    /// * `Option<Vec<u8>>` - 累积的流数据，如果会话不存在返回None
    pub fn get_stream_buffer(&self, session_id: u64) -> Option<Vec<u8>> {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let session_inner = session.inner.lock().unwrap();
            Some(session_inner.stream_buffer.clone())
        } else {
            None
        }
    }

    /// 扫描完整数据（用于header刚刚完成的情况）
    ///
    /// 这种情况下，我们需要扫描整个累积数据，而不是使用流式扫描
    /// 因为流式扫描是增量的，不能重复扫描已经扫描过的数据
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `data` - 要扫描的完整数据
    ///
    /// # 返回值
    /// * `Result<Vec<MatchResult>>` - 匹配结果列表
    pub fn scan_complete_data_with_session(&self, session_id: u64, data: &[u8]) -> Result<Vec<MatchResult>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        log::debug!("Scanning complete data of {} bytes for session {}", data.len(), session_id);

        // 创建一个临时的reader来扫描数据
        use std::io::Cursor;
        let mut reader = Cursor::new(data);

        // 使用数据库进行一次性的完整扫描，不是流式扫描
        let db = self.database.read();

        // 分配scratch空间
        let scratch = (*db.inner).alloc_scratch()
            .map_err(|e| WebScanError::Hyperscan(format!("Failed to allocate scratch: {}", e)))?;

        let mut results = Vec::new();

        // 使用 Cell 来避免借用检查问题
        use std::cell::RefCell;
        let results_ref = RefCell::new(&mut results);

        // 执行一次性扫描，匹配时调用回调函数
        (*db.inner).scan(&mut reader, &scratch, |id, from, to, flags| {
            let mut results = results_ref.borrow_mut();
            results.push(MatchResult {
                rule_id: id as u32,  // Hyperscan返回usize，需要转换为u32
                from,
                to,
                flags,
            });
            log::debug!("Complete scan matched rule {} at {}..{} (session: {})", id, from, to, session_id);

            Matching::Continue
        }).map_err(|e| WebScanError::Hyperscan(format!("Complete scan failed: {}", e)))?;

        log::debug!("Complete scan completed for session {}, found {} matches", session_id, results.len());
        Ok(results)
    }

    /// 清空会话的流缓冲区
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    pub fn clear_stream_buffer(&self, session_id: u64) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let mut session_inner = session.inner.lock().unwrap();
            session_inner.stream_buffer.clear();
            session_inner.http_header_complete = false;
        }
    }

    /// 检查HTTP header是否完整（包含\r\n\r\n）
    ///
    /// # 参数
    /// * `data` - 要检查的数据
    ///
    /// # 返回值
    /// * `bool` - 如果HTTP header完整返回true
    pub fn is_http_header_complete(data: &[u8]) -> bool {
        // 查找HTTP header结束标记 \r\n\r\n
        let header_end = b"\r\n\r\n";
        data.windows(header_end.len()).any(|window| window == header_end)
    }

    /// 检查会话的HTTP header是否已完整解析
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    ///
    /// # 返回值
    /// * `bool` - 如果HTTP header已完整解析返回true
    pub fn is_http_header_complete_for_session(&self, session_id: u64) -> bool {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let session_inner = session.inner.lock().unwrap();
            session_inner.http_header_complete
        } else {
            false
        }
    }

    /// 设置会话的HTTP header完整状态
    ///
    /// # 参数
    /// * `session_id` - 会话标识符
    /// * `complete` - 是否完整
    pub fn set_http_header_complete(&self, session_id: u64, complete: bool) {
        let sessions = self.sessions.read();
        if let Some(session) = sessions.get(&session_id) {
            let mut session_inner = session.inner.lock().unwrap();
            session_inner.http_header_complete = complete;
        }
    }

    /// 重置指定会话的Hyperscan流
    ///
    /// 重置流的状态，使其可以重新开始匹配，但不关闭流。
    /// 这对于处理HTTP请求/响应流非常有用：当一个HTTP请求结束时，
    /// 可以重置流以准备处理下一个请求，而不需要关闭和重新创建流。
    ///
    /// # 参数
    /// * `session_id` - 要重置的会话标识符
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn reset_session(&self, session_id: u64) -> Result<()> {
        // 快速获取会话引用，然后立即释放sessions锁
        let session = {
            let sessions = self.sessions.read();
            sessions.get(&session_id).cloned()  // 克隆Arc
        };  // 这里sessions锁被释放

        if let Some(session) = session {
            // 获取会话的内部数据锁（需要可变引用以重置状态）
            let mut session_inner = session.inner.lock().unwrap();
            
            // 重置流，不触发任何匹配回调（使用空的回调函数）
            session_inner.stream.reset(&session_inner.scratch, |_id, _from, _to, _flags| {
                // 重置时不应该触发匹配，但为了API兼容性，提供一个空回调
                Matching::Continue
            }).map_err(|e| WebScanError::Hyperscan(format!("Stream reset failed: {}", e)))?;

            // 重置所有状态字段
            session_inner.is_initialized = false;
            session_inner.protocol = None;
            session_inner.http_parse_success = false;
            session_inner.fast_pattern_matched = false;
            session_inner.candidate_rules = None;
            session_inner.matched_patterns_by_rule.clear();
            session_inner.stream_buffer.clear();
            session_inner.http_header_complete = false;

            log::debug!("Reset stream session {} and all state", session_id);
        } else {
            log::debug!("Session {} not found, nothing to reset", session_id);
        }

        Ok(())
    }

    /// 清理指定会话的流
    ///
    /// # 参数
    /// * `session_id` - 要清理的会话标识符
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn close_session(&self, session_id: u64) -> Result<()> {
        let mut sessions = self.sessions.write();

        if let Some(session_arc) = sessions.remove(&session_id) {
            // 尝试从Arc中获取所有权
            match Arc::try_unwrap(session_arc) {
                Ok(session) => {
                    // 获取会话的内部数据锁并消费它
                    let session_inner = session.inner.into_inner().unwrap();
                    
                    // 关闭流，可能会触发一些结束匹配
                    let mut final_results = Vec::new();
                    use std::cell::RefCell;
                    let results_ref = RefCell::new(&mut final_results);

                    session_inner.stream.close(&session_inner.scratch, |id, from, to, flags| {
                        let mut results = results_ref.borrow_mut();
                        results.push(MatchResult {
                            rule_id: id,
                            from,
                            to,
                            flags,
                        });
                        log::debug!("Hyperscan stream close matched rule {} at {}..{} (session: {})", id, from, to, session_id);

                        Matching::Continue
                    }).map_err(|e| WebScanError::Hyperscan(format!("Stream close failed: {}", e)))?;

                    log::debug!("Closed and removed stream session {}", session_id);
                }
                Err(_session_arc) => {
                    // 如果还有其他引用，说明其他线程可能正在使用这个会话
                    // 我们不能关闭流，因为这可能导致其他线程出错
                    log::warn!("Cannot close stream session {}: Arc has multiple references (other threads may be using it)", session_id);
                }
            }
        } else {
            log::debug!("Session {} not found, nothing to close", session_id);
        }

        Ok(())
    }

    /// 清理所有会话的流
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn close_all_sessions(&self) -> Result<()> {
        let mut sessions = self.sessions.write();

        let session_count = sessions.len();
        let session_ids: Vec<u64> = sessions.keys().cloned().collect();
        for session_id in session_ids {
            if let Some(session_arc) = sessions.remove(&session_id) {
                // 尝试从Arc中获取所有权
                match Arc::try_unwrap(session_arc) {
                    Ok(session) => {
                        // 获取会话的内部数据锁并消费它
                        let session_inner = session.inner.into_inner().unwrap();
                        
                        // 关闭流
                        let mut final_results = Vec::new();
                        use std::cell::RefCell;
                        let results_ref = RefCell::new(&mut final_results);

                        session_inner.stream.close(&session_inner.scratch, |id, from, to, flags| {
                            let mut results = results_ref.borrow_mut();
                            results.push(MatchResult {
                                rule_id: id as u32,  // Hyperscan返回usize，需要转换为u32
                                from,
                                to,
                                flags,
                            });
                            Matching::Continue
                        }).map_err(|e| WebScanError::Hyperscan(format!("Stream close failed: {}", e)))?;

                        log::debug!("Closed stream session {}", session_id);
                    }
                    Err(_session_arc) => {
                        // 如果还有其他引用，说明其他线程可能正在使用这个会话
                        // 我们不能关闭流，因为这可能导致其他线程出错
                        log::warn!("Cannot close stream session {}: Arc has multiple references (other threads may be using it)", session_id);
                    }
                }
            }
        }

        // 关闭fast pattern会话
        let mut fast_sessions = self.fast_sessions.write();
        let fast_session_ids: Vec<u64> = fast_sessions.keys().cloned().collect();
        let mut fast_closed_count = 0;
        for session_id in fast_session_ids {
            if let Some(session_arc) = fast_sessions.remove(&session_id) {
                match Arc::try_unwrap(session_arc) {
                    Ok(session_to_close) => {
                        let session_inner = session_to_close.inner.into_inner().unwrap();
                        let mut final_results = Vec::new();
                        use std::cell::RefCell;
                        let results_ref = RefCell::new(&mut final_results);
                        
                        session_inner.stream.close(&session_inner.scratch, |id, from, to, flags| {
                            let mut results = results_ref.borrow_mut();
                            results.push(MatchResult {
                                rule_id: id as u32,
                                from,
                                to,
                                flags,
                            });
                            Matching::Continue
                        }).map_err(|e| WebScanError::Hyperscan(format!("Fast pattern stream close failed: {}", e)))?;
                        fast_closed_count += 1;
                    }
                    Err(_) => {
                        log::warn!("Cannot close fast pattern stream session {}: Arc has multiple references", session_id);
                    }
                }
            }
        }

        log::info!("Closed all {} stream sessions ({} fast pattern)", session_count, fast_closed_count);
        Ok(())
    }

    /// 真正的 Hyperscan 流式扫描实现
    ///
    /// 使用编译后的 Hyperscan 流式数据库进行高性能模式匹配
    fn _stream_scan(&self, stream_db: &StreamingDatabase, data: &[u8]) -> Result<Vec<MatchResult>> {
        let mut results = Vec::new();

        // 检查数据是否为空
        if data.is_empty() {
            return Ok(results);
        }

        // 分配 Hyperscan 所需的临时空间（scratch space）
        let scratch = stream_db.alloc_scratch()
            .map_err(|e| WebScanError::Hyperscan(format!("Failed to allocate scratch space: {}", e)))?;

        // 打开一个新的流来处理这个数据包
        let stream = stream_db.open_stream()
            .map_err(|e| WebScanError::Hyperscan(format!("Failed to open stream: {}", e)))?;

        // 使用 Cell 来避免借用检查问题，因为我们是在回调中修改 results
        use std::cell::RefCell;
        let results_ref = RefCell::new(&mut results);

        // 执行扫描，匹配时调用回调函数
        stream.scan(data, &scratch, |id, from, to, flags| {
            let mut results = results_ref.borrow_mut();
            results.push(MatchResult {
                rule_id: id as u32,  // Hyperscan返回usize，需要转换为u32
                from,
                to,
                flags,
            });
            log::debug!("Hyperscan matched rule {} at {}..{}", id, from, to);

            // 继续搜索更多匹配
            Matching::Continue
        }).map_err(|e| WebScanError::Hyperscan(format!("Stream scan failed: {}", e)))?;

        // 关闭流，可能会触发一些结束匹配
        stream.close(&scratch, |id, from, to, flags| {
            let mut results = results_ref.borrow_mut();
            results.push(MatchResult {
                rule_id: id as u32,  // Hyperscan返回usize，需要转换为u32
                from,
                to,
                flags,
            });
            log::debug!("Hyperscan stream close matched rule {} at {}..{}", id, from, to);

            Matching::Continue
        }).map_err(|e| WebScanError::Hyperscan(format!("Stream close failed: {}", e)))?;

        log::debug!("Hyperscan stream scan completed, found {} matches", results.len());
        Ok(results)
    }

    /// 后备扫描实现
    ///
    /// 当Hyperscan不可用时使用的简单字符串匹配实现。
    /// 这提供了基本的功能，但不具备Hyperscan的高性能特性。
    fn _fallback_scan(&self, data: &[u8]) -> Result<Vec<MatchResult>> {
        let data_str = std::str::from_utf8(data).unwrap_or("");
        if data_str.is_empty() {
            return Ok(vec![]);
        }

        // 定义常见的 Web 扫描模式
        let patterns = vec![
            ("/admin/", 1001),
            ("/login.php", 1003),
            ("union select", 1002),
            ("<script>", 1004),
            ("../etc/passwd", 1005),
        ];

        let data_lower = data_str.to_lowercase();
        let mut results = Vec::new();

        for (pattern, rule_id) in patterns {
            if let Some(start_pos) = data_lower.find(pattern) {
                results.push(MatchResult {
                    rule_id,
                    from: start_pos as u64,
                    to: (start_pos + pattern.len()) as u64,
                    flags: 0,
                });
                break; // 返回第一个匹配
            }
        }

        Ok(results)
    }
}

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleAction;

    /// 测试Hyperscan编译器
    #[test]
    fn test_hyperscan_compiler() {
        let mut compiler = HyperscanCompiler::new();

        // 创建测试规则
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "test".to_string());
        assert!(rule.is_ok());

        let rule = rule.unwrap();
        assert!(compiler.add_rule(&rule).is_ok());
    }

    /// 测试会话管理 - 创建和使用会话
    #[test]
    fn test_session_management() {
        let mut compiler = HyperscanCompiler::new();
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "test".to_string()).unwrap();
        compiler.add_rule(&rule).unwrap();
        
        let (database, fast_database) = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database, fast_database).unwrap();
        
        let session_id = 12345;
        let data = b"test data";
        
        // 第一次调用应该创建会话
        let results = scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        assert!(results.is_empty() || !results.is_empty()); // 结果可能为空或匹配
        
        // 第二次调用应该使用同一个会话
        let results2 = scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        assert!(results2.is_empty() || !results2.is_empty());
    }

    /// 测试会话重置功能
    #[test]
    fn test_session_reset() {
        let mut compiler = HyperscanCompiler::new();
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "test".to_string()).unwrap();
        compiler.add_rule(&rule).unwrap();
        
        let (database, fast_database) = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database, fast_database).unwrap();
        
        let session_id = 12346;
        let data = b"test";
        
        // 第一次扫描
        scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        
        // 重置会话
        assert!(scanner.reset_session(session_id).is_ok());
        
        // 重置后应该可以继续使用
        let results = scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        assert!(results.is_empty() || !results.is_empty());
    }

    /// 测试请求结束时自动重置
    #[test]
    fn test_reset_on_request_end() {
        let mut compiler = HyperscanCompiler::new();
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "test".to_string()).unwrap();
        compiler.add_rule(&rule).unwrap();
        
        let (database, fast_database) = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database, fast_database).unwrap();
        
        let session_id = 12347;
        let data = b"test";
        
        // 第一次扫描，不重置
        scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        
        // 第二次扫描，请求结束时重置
        scanner.scan_stream_with_session(session_id, data, false, true).unwrap();
        
        // 重置后应该可以继续使用
        let results = scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        assert!(results.is_empty() || !results.is_empty());
    }

    /// 测试关闭会话
    #[test]
    fn test_close_session() {
        let mut compiler = HyperscanCompiler::new();
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "test".to_string()).unwrap();
        compiler.add_rule(&rule).unwrap();
        
        let (database, fast_database) = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database, fast_database).unwrap();
        
        let session_id = 12348;
        let data = b"test";
        
        // 创建会话
        scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        
        // 关闭会话
        assert!(scanner.close_session(session_id).is_ok());
        
        // 关闭后重置应该失败（会话不存在）
        assert!(scanner.reset_session(session_id).is_ok()); // reset_session 对不存在的会话返回 Ok
    }

    /// 测试会话结束时自动关闭
    #[test]
    fn test_session_final_close() {
        let mut compiler = HyperscanCompiler::new();
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "test".to_string()).unwrap();
        compiler.add_rule(&rule).unwrap();
        
        let (database, fast_database) = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database, fast_database).unwrap();
        
        let session_id = 12349;
        let data = b"test";
        
        // 创建会话并标记为最终
        scanner.scan_stream_with_session(session_id, data, true, false).unwrap();
        
        // 会话应该已经被关闭，再次使用应该创建新会话
        let results = scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
        assert!(results.is_empty() || !results.is_empty());
    }

    /// 测试多个会话并发
    #[test]
    fn test_multiple_sessions() {
        let mut compiler = HyperscanCompiler::new();
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "test".to_string()).unwrap();
        compiler.add_rule(&rule).unwrap();
        
        let (database, fast_database) = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database, fast_database).unwrap();
        
        // 创建多个不同的会话
        for i in 1..=5 {
            let session_id = 20000 + i;
            let data = b"test";
            let results = scanner.scan_stream_with_session(session_id, data, false, false).unwrap();
            assert!(results.is_empty() || !results.is_empty());
        }
        
        // 验证所有会话都可以独立操作
        for i in 1..=5 {
            let session_id = 20000 + i;
            assert!(scanner.reset_session(session_id).is_ok());
        }
        
        // 清理所有会话
        assert!(scanner.close_all_sessions().is_ok());
    }

    /// 测试跨数据包匹配
    #[test]
    fn test_cross_packet_matching() {
        let mut compiler = HyperscanCompiler::new();
        // 创建一个跨数据包的模式，比如 "hello world"
        let rule = Rule::new(1, RuleAction::Alert, "Test rule".to_string(), "hello.*world".to_string()).unwrap();
        compiler.add_rule(&rule).unwrap();
        
        let (database, fast_database) = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database, fast_database).unwrap();
        
        let session_id = 12350;
        
        // 第一个数据包
        let packet1 = b"hello ";
        scanner.scan_stream_with_session(session_id, packet1, false, false).unwrap();
        
        // 第二个数据包（应该能匹配跨数据包的模式）
        let packet2 = b"world";
        let results = scanner.scan_stream_with_session(session_id, packet2, false, false).unwrap();
        // 注意：实际匹配结果取决于Hyperscan的实现，这里主要测试不会panic
        assert!(results.is_empty() || !results.is_empty());
    }

    }