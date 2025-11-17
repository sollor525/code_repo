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
use crate::rules::{Rule, RuleAction};
// 导入Hyperscan库
use hyperscan::{StreamingDatabase, Pattern, Patterns, Matching, Builder, Streaming};
// 导入同步原语
use parking_lot::RwLock;
// 导入原子类型和智能指针
use std::sync::Arc;
// 导入字符串类型
use std::string::String;

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

/// Hyperscan扫描器
///
/// 提供高性能模式匹配功能。
pub struct HyperscanScanner {
    database: Arc<RwLock<HyperscanDatabase>>,  // 数据库实例
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
        })
    }

    /// 执行流式模式扫描
    ///
    /// # 参数
    /// * `data` - 要扫描的数据
    ///
    /// # 返回值
    /// * `Result<Vec<MatchResult>>` - 匹配结果列表
    pub fn scan_stream(&self, data: &[u8]) -> Result<Vec<MatchResult>> {
        let db = self.database.read();

        // 直接使用流式数据库进行扫描
        self._stream_scan(&db.inner, data)
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

    }