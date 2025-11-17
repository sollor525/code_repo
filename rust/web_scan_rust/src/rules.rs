//! 规则管理和解析模块
//! 
//! 负责加载、解析和管理Web扫描检测规则。
//! 支持Suricata格式的规则文件，提供高效的规则匹配功能。

// 导入错误处理类型
use crate::error::{Result, WebScanError};
// 导入正则表达式库，用于复杂的模式匹配
use regex::Regex;
// 导入序列化/反序列化trait，用于配置文件处理
use serde::Deserialize;
// 导入HashMap，用于快速查找规则
use std::collections::HashMap;
// 导入文件系统操作
use std::fs;
// 导入路径处理
use std::path::Path;

/// 规则动作枚举
/// 
/// 定义当规则匹配时应该执行的动作类型。
/// 这些动作决定了检测到威胁时系统的响应方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]  // C兼容的内存布局
pub enum RuleAction {
    None = 0,   // 无动作（通常用于测试）
    Alert = 1,  // 仅告警，不阻断流量
    Drop = 2,   // 丢弃数据包
    Reset = 3,  // 发送TCP重置包
}

// 为RuleAction实现Default trait
// 默认动作是Alert（告警），这是最安全的选择
impl Default for RuleAction {
    fn default() -> Self {
        RuleAction::Alert
    }
}

/// 检测规则结构体
/// 
/// 表示一个完整的Web扫描检测规则，包含匹配模式、动作和元数据。
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,                                    // 规则唯一标识符
    pub action: RuleAction,                         // 匹配时执行的动作
    pub message: String,                            // 规则描述信息
    pub pattern: String,                            // 原始匹配模式
    pub compiled_regex: Option<Regex>,              // 编译后的正则表达式（可选）
    pub metadata: HashMap<String, String>,          // 额外的元数据
}

impl Rule {
    /// 创建新的规则实例
    /// 
    /// # 参数
    /// * `id` - 规则ID，必须唯一
    /// * `action` - 匹配时的动作
    /// * `message` - 规则描述
    /// * `pattern` - 匹配模式（可以是简单字符串或正则表达式）
    /// 
    /// # 返回值
    /// * `Result<Self>` - 成功时返回Rule实例，失败时返回错误
    pub fn new(id: u32, action: RuleAction, message: String, pattern: String) -> Result<Self> {
        // 尝试编译正则表达式（如果模式不为空）
        let compiled_regex = if pattern.is_empty() {
            None  // 空模式不需要正则表达式
        } else {
            // 尝试编译正则表达式
            // map_err()用于转换错误类型
            Some(Regex::new(&pattern).map_err(|e| {
                // 如果正则表达式编译失败，创建自定义错误
                WebScanError::RuleParsing(format!("Invalid regex pattern '{}': {}", pattern, e))
            })?)  // ?操作符传播错误
        };

        // 创建并返回Rule实例
        Ok(Rule {
            id,
            action,
            message,
            pattern,
            compiled_regex,
            metadata: HashMap::new(),  // 初始化为空的HashMap
        })
    }

    /// 检查此规则是否匹配给定内容
    /// 
    /// # 参数
    /// * `content` - 要检查的内容字符串
    /// 
    /// # 返回值
    /// * `bool` - 如果匹配返回true，否则返回false
    pub fn matches(&self, content: &str) -> bool {
        // 使用模式匹配检查是否有编译的正则表达式
        match &self.compiled_regex {
            // 如果有正则表达式，使用正则匹配
            Some(regex) => regex.is_match(content),
            // 如果没有正则表达式，使用简单的字符串包含检查
            None => content.contains(&self.pattern),
        }
    }

    /// 添加元数据键值对
    /// 
    /// 元数据用于存储规则的额外信息，如分类、优先级等。
    /// 
    /// # 参数
    /// * `key` - 元数据键
    /// * `value` - 元数据值
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// 获取元数据值
    /// 
    /// # 参数
    /// * `key` - 要查找的元数据键
    /// 
    /// # 返回值
    /// * `Option<&String>` - 如果找到返回Some(值)，否则返回None
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// 规则管理器结构体
/// 
/// 负责管理所有检测规则，包括加载、存储、查找和匹配规则。
/// 使用HashMap提供O(1)时间复杂度的规则查找。
pub struct RuleManager {
    rules: HashMap<u32, Rule>,           // 规则存储：ID -> Rule
    rule_count: u32,                     // 当前规则总数
    enabled: bool,                       // 是否启用规则管理
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleManager {
    /// 创建新的规则管理器实例
    /// 
    /// 初始化空的规则集合和默认配置。
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),        // 创建空的HashMap
            rule_count: 0,                // 初始规则数量为0
            enabled: true,                // 默认启用
        }
    }

    /// 添加新规则
    /// 
    /// # 参数
    /// * `rule` - 要添加的规则实例
    /// 
    /// # 返回值
    /// * `Result<()>` - 成功返回Ok(())，失败返回错误
    pub fn add_rule(&mut self, rule: Rule) -> Result<()> {
        // 检查规则ID是否已存在
        if self.rules.contains_key(&rule.id) {
            return Err(WebScanError::RuleParsing(
                format!("Rule with ID {} already exists", rule.id)
            ));
        }

        // 将规则添加到HashMap中
        self.rules.insert(rule.id, rule);
        self.rule_count += 1;            // 增加规则计数
        
        Ok(())
    }

    /// 根据ID查找规则
    /// 
    /// # 参数
    /// * `id` - 要查找的规则ID
    /// 
    /// # 返回值
    /// * `Option<&Rule>` - 如果找到返回Some(规则引用)，否则返回None
    pub fn get_rule(&self, id: u32) -> Option<&Rule> {
        self.rules.get(&id)
    }

    /// 移除指定ID的规则
    /// 
    /// # 参数
    /// * `id` - 要移除的规则ID
    /// 
    /// # 返回值
    /// * `bool` - 如果成功移除返回true，如果规则不存在返回false
    pub fn remove_rule(&mut self, id: u32) -> bool {
        // remove()方法返回Option<Rule>，如果存在则返回Some(规则)，否则返回None
        if let Some(_) = self.rules.remove(&id) {
            self.rule_count -= 1;        // 减少规则计数
            true
        } else {
            false
        }
    }

    /// 获取所有规则
    /// 
    /// # 返回值
    /// * `&HashMap<u32, Rule>` - 所有规则的引用
    pub fn get_all_rules(&self) -> &HashMap<u32, Rule> {
        &self.rules
    }

    /// 获取规则总数
    /// 
    /// # 返回值
    /// * `u32` - 当前规则总数
    pub fn rule_count(&self) -> u32 {
        self.rule_count
    }

    /// 检查内容是否匹配任何规则
    /// 
    /// 这是规则管理的核心功能，遍历所有规则检查是否有匹配。
    /// 
    /// # 参数
    /// * `content` - 要检查的内容
    /// 
    /// # 返回值
    /// * `Option<&Rule>` - 如果匹配到规则返回Some(规则引用)，否则返回None
    pub fn match_content(&self, content: &str) -> Option<&Rule> {
        // 如果规则管理未启用，直接返回None
        if !self.enabled {
            return None;
        }

        // 遍历所有规则，找到第一个匹配的
        // iter()创建迭代器，find()找到第一个满足条件的元素
        self.rules.values().find(|rule| rule.matches(content))
    }

    /// 从文件加载规则
    ///
    /// 支持多种格式的规则文件，如JSON、TOML、Hyperscan等。
    ///
    /// # 参数
    /// * `path` - 规则文件路径
    ///
    /// # 返回值
    /// * `Result<u32>` - 成功返回加载的规则数量，失败返回错误
    pub fn load_rules_from_file(&mut self, path: &Path) -> Result<u32> {
        // 读取文件内容
        let content = fs::read_to_string(path)?;
        
        // 根据文件扩展名选择解析方法
        let loaded_count = match path.extension().and_then(|s| s.to_str()) {
            Some("json") => self.parse_json_rules(&content)?,
            Some("toml") => self.parse_toml_rules(&content)?,
            Some("rules") => self.parse_hyperscan_rules(&content)?,
            Some("hs") => self.parse_hyperscan_rules(&content)?,
            _ => return Err(WebScanError::RuleParsing(
                "Unsupported file format. Only JSON, TOML, and Hyperscan (.rules/.hs) are supported.".to_string()
            )),
        };

        Ok(loaded_count)
    }

    /// 解析Hyperscan格式的规则
    ///
    /// 支持Suricata/Snort风格的规则格式。
    ///
    /// # 参数
    /// * `content` - Hyperscan格式的规则内容
    ///
    /// # 返回值
    /// * `Result<u32>` - 成功返回解析的规则数量，失败返回错误
    fn parse_hyperscan_rules(&mut self, content: &str) -> Result<u32> {
        let mut loaded_count = 0;
        
        // 按行分割规则内容
        for (line_num, line) in content.lines().enumerate() {
            // 跳过空行和注释行
            let trimmed_line = line.trim();
            if trimmed_line.is_empty() || trimmed_line.starts_with('#') {
                continue;
            }
            
            // 解析Suricata/Snort格式规则
            // 格式: action protocol source_ip source_port -> dest_ip dest_port (options)
            if let Ok(rule) = self._parse_suricata_rule(trimmed_line, line_num + 1) {
                self.add_rule(rule)?;
                loaded_count += 1;
            }
        }
        
        Ok(loaded_count)
    }

    /// 解析单个Suricata/Snort规则
    ///
    /// # 参数
    /// * `rule_line` - 规则行内容
    /// * `line_num` - 行号（用于错误报告）
    ///
    /// # 返回值
    /// * `Result<Rule>` - 解析后的规则
    fn _parse_suricata_rule(&self, rule_line: &str, line_num: usize) -> Result<Rule> {
        // 简单的规则解析，支持基本的Suricata格式
        // 示例: alert http any any -> any any (msg:"Admin access"; content:"/admin/"; sid:1001;)
        
        // 提取动作部分
        let parts: Vec<&str> = rule_line.split_whitespace().collect();
        if parts.len() < 7 {
            return Err(WebScanError::RuleParsing(
                format!("Invalid rule format at line {}: insufficient parts", line_num)
            ));
        }
        
        let action_str = parts[0];
        let action = match action_str {
            "alert" => RuleAction::Alert,
            "drop" => RuleAction::Drop,
            "reset" => RuleAction::Reset,
            "pass" | "none" => RuleAction::None,
            _ => return Err(WebScanError::RuleParsing(
                format!("Invalid action '{}' at line {}", action_str, line_num)
            )),
        };
        
        // 检查是否为HTTP规则
        if parts[1] != "http" {
            return Err(WebScanError::RuleParsing(
                format!("Only HTTP rules are supported at line {}", line_num)
            ));
        }
        
        // 提取选项部分
        let options_start = rule_line.find('(');
        let options_end = rule_line.rfind(')');
        
        if options_start.is_none() || options_end.is_none() || options_end.unwrap() <= options_start.unwrap() {
            return Err(WebScanError::RuleParsing(
                format!("Invalid options format at line {}", line_num)
            ));
        }
        
        let options_str = &rule_line[options_start.unwrap() + 1..options_end.unwrap()];
        
        // 解析选项
        let mut message = "Unknown rule".to_string();
        let mut pattern = String::new();
        let mut sid = 0u32;
        
        for option in options_str.split(';') {
            let option = option.trim();
            if option.is_empty() {
                continue;
            }
            
            if let Some(eq_pos) = option.find(':') {
                let key = &option[..eq_pos];
                let value = &option[eq_pos + 1..].trim_matches('"');
                
                match key {
                    "msg" => message = value.to_string(),
                    "content" => pattern = value.to_string(),
                    "sid" => {
                        sid = value.parse().map_err(|_| {
                            WebScanError::RuleParsing(
                                format!("Invalid SID '{}' at line {}", value, line_num)
                            )
                        })?;
                    }
                    _ => {} // 忽略其他选项
                }
            }
        }
        
        if sid == 0 {
            return Err(WebScanError::RuleParsing(
                format!("Missing or invalid SID at line {}", line_num)
            ));
        }
        
        if pattern.is_empty() {
            return Err(WebScanError::RuleParsing(
                format!("Missing content pattern at line {}", line_num)
            ));
        }
        
        // 创建规则
        Rule::new(sid, action, message, pattern)
    }

    /// 解析JSON格式的规则
    /// 
    /// # 参数
    /// * `json_content` - JSON格式的规则内容
    /// 
    /// # 返回值
    /// * `Result<u32>` - 成功返回解析的规则数量，失败返回错误
    fn parse_json_rules(&mut self, json_content: &str) -> Result<u32> {
        // 定义JSON规则的结构
        #[derive(Deserialize)]
        struct JsonRule {
            id: u32,
            action: String,
            message: String,
            pattern: String,
            #[serde(default)]
            metadata: HashMap<String, String>,
        }

        // 解析JSON数组
        let json_rules: Vec<JsonRule> = serde_json::from_str(json_content)?;
        let mut loaded_count = 0;

        // 遍历解析的规则
        for json_rule in json_rules {
            // 将字符串动作转换为RuleAction枚举
            let action = match json_rule.action.as_str() {
                "alert" => RuleAction::Alert,
                "drop" => RuleAction::Drop,
                "reset" => RuleAction::Reset,
                "none" => RuleAction::None,
                _ => return Err(WebScanError::RuleParsing(
                    format!("Invalid action '{}' for rule {}", json_rule.action, json_rule.id)
                )),
            };

            // 创建Rule实例
            let mut rule = Rule::new(
                json_rule.id,
                action,
                json_rule.message,
                json_rule.pattern,
            )?;

            // 添加元数据
            for (key, value) in json_rule.metadata {
                rule.add_metadata(key, value);
            }

            // 添加到规则管理器
            self.add_rule(rule)?;
            loaded_count += 1;
        }

        Ok(loaded_count)
    }

    /// 解析TOML格式的规则
    /// 
    /// # 参数
    /// * `toml_content` - TOML格式的规则内容
    /// 
    /// # 返回值
    /// * `Result<u32>` - 成功返回解析的规则数量，失败返回错误
    fn parse_toml_rules(&mut self, toml_content: &str) -> Result<u32> {
        // 定义TOML规则的结构
        #[derive(Deserialize)]
        struct TomlRule {
            id: u32,
            action: String,
            message: String,
            pattern: String,
            #[serde(default)]
            metadata: HashMap<String, String>,
        }

        #[derive(Deserialize)]
        struct TomlRules {
            rules: Vec<TomlRule>,
        }

        // 解析TOML内容
        let toml_rules: TomlRules = toml::from_str(toml_content)?;
        let mut loaded_count = 0;

        // 遍历解析的规则
        for toml_rule in toml_rules.rules {
            // 将字符串动作转换为RuleAction枚举
            let action = match toml_rule.action.as_str() {
                "alert" => RuleAction::Alert,
                "drop" => RuleAction::Drop,
                "reset" => RuleAction::Reset,
                "none" => RuleAction::None,
                _ => return Err(WebScanError::RuleParsing(
                    format!("Invalid action '{}' for rule {}", toml_rule.action, toml_rule.id)
                )),
            };

            // 创建Rule实例
            let mut rule = Rule::new(
                toml_rule.id,
                action,
                toml_rule.message,
                toml_rule.pattern,
            )?;

            // 添加元数据
            for (key, value) in toml_rule.metadata {
                rule.add_metadata(key, value);
            }

            // 添加到规则管理器
            self.add_rule(rule)?;
            loaded_count += 1;
        }

        Ok(loaded_count)
    }

    /// 启用或禁用规则管理
    /// 
    /// # 参数
    /// * `enabled` - 是否启用
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// 检查规则管理是否启用
    /// 
    /// # 返回值
    /// * `bool` - 如果启用返回true，否则返回false
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 清空所有规则
    /// 
    /// 移除所有已加载的规则，重置规则计数。
    pub fn clear_rules(&mut self) {
        self.rules.clear();              // 清空HashMap
        self.rule_count = 0;             // 重置计数
    }
}

// 条件编译：只在测试时编译以下代码
#[cfg(test)]
mod tests {
    // 导入父模块的所有公共项
    use super::*;

    /// 测试规则创建和匹配
    #[test]
    fn test_rule_creation_and_matching() {
        // 创建测试规则
        let rule = Rule::new(
            1,
            RuleAction::Alert,
            "Test rule".to_string(),
            "test".to_string(),
        ).unwrap();

        // 测试匹配功能
        assert!(rule.matches("This is a test message"));
        assert!(!rule.matches("This message doesn't contain the pattern"));
    }

    /// 测试规则管理器
    #[test]
    fn test_rule_manager() {
        let mut manager = RuleManager::new();
        
        // 创建测试规则
        let rule1 = Rule::new(1, RuleAction::Alert, "Rule 1".to_string(), "pattern1".to_string()).unwrap();
        let rule2 = Rule::new(2, RuleAction::Drop, "Rule 2".to_string(), "pattern2".to_string()).unwrap();
        
        // 添加规则
        manager.add_rule(rule1).unwrap();
        manager.add_rule(rule2).unwrap();
        
        // 验证规则数量
        assert_eq!(manager.rule_count(), 2);
        
        // 测试内容匹配
        assert!(manager.match_content("This contains pattern1").is_some());
        assert!(manager.match_content("This contains pattern2").is_some());
        assert!(manager.match_content("This contains nothing").is_none());
    }

    /// 测试重复规则ID的处理
    #[test]
    fn test_duplicate_rule_id() {
        let mut manager = RuleManager::new();
        
        let rule1 = Rule::new(1, RuleAction::Alert, "Rule 1".to_string(), "pattern1".to_string()).unwrap();
        let rule2 = Rule::new(1, RuleAction::Drop, "Rule 2".to_string(), "pattern2".to_string()).unwrap();
        
        // 第一个规则应该成功添加
        manager.add_rule(rule1).unwrap();
        
        // 第二个规则应该失败（ID重复）
        assert!(manager.add_rule(rule2).is_err());
    }
}