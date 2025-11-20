//! PCRE功能测试程序
//!
//! 这个程序用于测试新的PCRE字段支持功能

use web_scan_rust::rules::RuleManager;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    env_logger::init();

    println!("PCRE功能测试开始...");

    // 创建规则管理器
    let mut rule_manager = RuleManager::new();

    // 加载PCRE测试规则
    let rules_path = Path::new("examples/pcre_test.rules");
    if rules_path.exists() {
        println!("正在加载PCRE测试规则...");
        let loaded_count = rule_manager.load_rules_from_file(rules_path)?;
        println!("成功加载 {} 条规则", loaded_count);

        // 显示加载的规则信息
        println!("\n=== 规则详情 ===");
        for (rule_id, rule) in rule_manager.get_all_rules() {
            println!("规则 {}: {}", rule_id, rule.message);
            println!("  动作: {:?}", rule.action);
            println!("  Content模式数量: {}", rule.patterns.len());
            println!("  PCRE模式数量: {}", rule.pcre_patterns.len());

            // 显示content模式
            for (i, pattern) in rule.patterns.iter().enumerate() {
                println!("  Content {}: '{}' (位置: {:?})", i, pattern.pattern, pattern.http_location);
            }

            // 显示PCRE模式
            for (i, pcre) in rule.pcre_patterns.iter().enumerate() {
                println!("  PCRE {}: '{}' (类型: {:?}, 位置: {:?})",
                         i, pcre.raw_pattern, pcre.match_type, pcre.http_location);
            }
            println!();
        }

        // 测试规则匹配
        println!("=== 测试规则匹配 ===");

        let test_data = vec![
            ("http://example.com/test", "基本PCRE测试"),
            ("http://example.com/admin/login", "URI中的PCRE"),
            ("POST /login\nusername=admin\npassword=secret", "HTTP Body中的PCRE"),
            ("GET /wp-admin/", "传统content测试"),
        ];

        for (data, description) in test_data {
            println!("\n测试数据: {} - '{}'", description, data);

            // 简单的HTTP解析（这里我们使用简化的测试）
            if let Some(rule) = rule_manager.match_content(data) {
                println!("  -> 匹配规则 {}: {}", rule.id, rule.message);

                // 测试PCRE匹配
                if rule.has_pcre_patterns() {
                    println!("  -> 规则有PCRE模式，测试PCRE匹配: {}", rule.pcre_matches(data));
                }
            } else {
                println!("  -> 未匹配任何规则");
            }
        }

    } else {
        println!("错误: 找不到测试规则文件 'examples/pcre_test.rules'");
        return Err("测试规则文件不存在".into());
    }

    println!("\nPCRE功能测试完成！");
    Ok(())
}