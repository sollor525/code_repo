// 测试单个9010000规则的加载

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_9010001_rule_loading() {
        println!("🔍 测试单个9010000规则加载");
        println!("================================");

        // 创建一个临时的简单规则文件
        let rule_content = r#"alert http any any -> any any (msg:"HTTP Attack: DEBUG method detected"; content:"DEBUG"; http.method; nocase; sid:9010001; rev:1;)"#;

        // 1. 初始化引擎
        let engine = web_scan_rust::engine::WebScanEngine::new();
        if engine.is_err() {
            println!("❌ 引擎初始化失败: {:?}", engine.unwrap_err());
            return;
        }
        println!("✅ 引擎初始化成功");

        // 2. 尝试加载规则
        println!("规则内容: {}", rule_content);

        match web_scan_rust::rules::RuleLoader::load_from_content(rule_content) {
            Ok(rules) => {
                println!("✅ 规则解析成功，规则数: {}", rules.len());

                for rule in &rules {
                    println!("📋 规则 {}: SID={}, 动作={:?}, 模式数={}",
                            rule.rule_id, rule.action, rule.patterns.len());

                    for pattern in &rule.patterns {
                        println!("   -> 模式: '{}' (位置: {:?}, 大小写: {}, 转义: {})",
                            pattern.content, pattern.http_location, pattern.nocase, pattern.escaped);
                    }
                }

                // 3. 将规则加载到引擎
                match engine.add_rules(rules) {
                    Ok(_) => {
                        println!("✅ 规则成功添加到引擎");

                        // 获取统计
                        match engine.get_stats() {
                            Ok(stats) => {
                                println!("📊 引擎统计:");
                                println!("   已加载规则数: {}", stats.rules_loaded);
                                println!("   活跃规则数: {}", stats.rules_active);
                            }
                            Err(e) => {
                                println!("❌ 获取统计失败: {}", e);
                            }
                        }

                        // 4. 测试检测
                        let test_payload = b"DEBUG /admin HTTP/1.1\r\nHost: test.com\r\n\r\n";
                        match engine.process_payload(test_payload.as_bytes()) {
                            Ok(result) => {
                                println!("🔍 测试结果:");
                                println!("   输入: DEBUG /admin HTTP/1.1");
                                if result.is_matched {
                                    println!("   ✅ 匹配成功: SID={}, 动作={:?}", result.rule_id, result.action);
                                } else {
                                    println!("   ❌ 未匹配");
                                }
                            }
                            Err(e) => {
                                println!("❌ 检测失败: {}", e);
                            }
                        }

                        engine.cleanup().ok();
                    }
                    Err(e) => {
                        println!("❌ 规则添加到引擎失败: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("❌ 规则解析失败: {}", e);
            }
        }
    }
}