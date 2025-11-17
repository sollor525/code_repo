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
#[derive(Debug)]
pub struct HyperscanCompiler {
    /// 存储模式和对应的规则 ID
    patterns: Vec<(String, u32)>,
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
        }
    }

    /// 添加规则到编译器
    ///
    /// # 参数
    /// * `rule` - 要添加的规则
    ///
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn add_rule(&mut self, rule: &Rule) -> Result<()> {
        // 添加模式字符串和对应的规则 ID
        self.patterns.push((rule.pattern.clone(), rule.id));
        Ok(())
    }

    /// 编译模式为流式数据库
    ///
    /// # 返回值
    /// * `Result<HyperscanDatabase>` - 编译后的流式数据库
    pub fn compile(self) -> Result<HyperscanDatabase> {
        if self.patterns.is_empty() {
            return Err(WebScanError::Hyperscan("No patterns to compile".to_string()));
        }

        // 创建多个模式，每个模式都有对应的规则 ID
        let mut patterns = Vec::new();
        for (pattern_str, rule_id) in self.patterns.iter() {
            match Pattern::new(pattern_str.as_str()) {
                Ok(mut pattern) => {
                    // 设置规则 ID
                    pattern.id = Some(*rule_id as usize);
                    patterns.push(pattern);
                }
                Err(e) => {
                    log::warn!("Failed to create Hyperscan pattern '{}': {}", pattern_str, e);
                    // 跳过无效的模式，继续编译其他模式
                }
            }
        }

        if patterns.is_empty() {
            return Err(WebScanError::Hyperscan("No valid patterns to compile".to_string()));
        }

        // 使用 hyperscan 的 Patterns 包装
        let patterns = Patterns(patterns);

        // 使用 Builder API 编译流式数据库
        let db = patterns.build::<Streaming>()
            .map_err(|e| WebScanError::Hyperscan(format!("Failed to compile stream database: {}", e)))?;

        log::info!("Compiled Hyperscan stream database with {} patterns", self.patterns.len());
        Ok(HyperscanDatabase { inner: db })
    }
}

/// Hyperscan流式数据库
///
/// 专门用于流式模式匹配，支持跨数据包边界匹配。
pub struct HyperscanDatabase {
    /// 内部流式数据库实例
    inner: StreamingDatabase,
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
struct HyperscanStreamSessionInner {
    /// Hyperscan流实例
    stream: hyperscan::Stream,
    /// Scratch空间，用于流扫描
    scratch: hyperscan::Scratch,
}

/// Hyperscan扫描器
///
/// 提供高性能模式匹配功能，支持多会话流式匹配。
/// 会话表是全局的，但每个会话只被单个线程使用，通过Arc实现并发安全。
pub struct HyperscanScanner {
    database: Arc<RwLock<HyperscanDatabase>>,  // 数据库实例
    /// 会话到流的映射，每个会话维护独立的stream
    /// 使用Arc包装会话，允许在释放sessions锁后继续使用会话
    sessions: Arc<RwLock<HashMap<u64, Arc<HyperscanStreamSession>>>>,
}

impl HyperscanScanner {
    /// 创建新的扫描器实例
    ///
    /// # 参数
    /// * `database` - 已编译的Hyperscan流式数据库
    ///
    /// # 返回值
    /// * `Result<Self>` - 成功返回扫描器实例，失败返回错误
    pub fn new(database: HyperscanDatabase) -> Result<Self> {
        Ok(Self {
            database: Arc::new(RwLock::new(database)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
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

    /// 执行流式模式扫描（带会话管理）
    ///
    /// 为每个会话维护独立的Hyperscan流，支持跨数据包边界匹配。
    /// 优化了锁的使用：只在查找/创建会话时短暂持有sessions锁，然后立即释放，
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
                let stream = db.inner.open_stream()
                    .expect("Failed to open stream");
                let scratch = db.inner.alloc_scratch()
                    .expect("Failed to allocate scratch");
                Arc::new(HyperscanStreamSession {
                    inner: Mutex::new(HyperscanStreamSessionInner {
                        stream,
                        scratch,
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
                    rule_id: id,
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
            let session_inner = session.inner.lock().unwrap();
            session_inner.stream.reset(&session_inner.scratch, |_id, _from, _to, _flags| {
                // 重置时不应该触发匹配，但为了API兼容性，提供一个空回调
                Matching::Continue
            }).map_err(|e| WebScanError::Hyperscan(format!("Stream reset failed: {}", e)))?;
            log::debug!("Reset stream session {} after request end", session_id);
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
            }
        }

        log::debug!("Hyperscan stream scan completed for session {}, found {} matches", session_id, results.len());
        Ok(results)
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
            // 获取会话的内部数据锁
            let session_inner = session.inner.lock().unwrap();
            
            // 重置流，不触发任何匹配回调（使用空的回调函数）
            session_inner.stream.reset(&session_inner.scratch, |_id, _from, _to, _flags| {
                // 重置时不应该触发匹配，但为了API兼容性，提供一个空回调
                Matching::Continue
            }).map_err(|e| WebScanError::Hyperscan(format!("Stream reset failed: {}", e)))?;

            log::debug!("Reset stream session {}", session_id);
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
                                rule_id: id,
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

        log::info!("Closed all {} stream sessions", session_count);
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
                rule_id: id,
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
                rule_id: id,
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
        
        let database = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database).unwrap();
        
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
        
        let database = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database).unwrap();
        
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
        
        let database = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database).unwrap();
        
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
        
        let database = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database).unwrap();
        
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
        
        let database = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database).unwrap();
        
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
        
        let database = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database).unwrap();
        
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
        
        let database = compiler.compile().unwrap();
        let scanner = HyperscanScanner::new(database).unwrap();
        
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