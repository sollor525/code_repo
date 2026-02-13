// This is a complete replacement for the broken parse_hyperscan_rules function
// Replace from line 1486 to 1849 in src/rules.rs

    /// 解析Hyperscan格式的规则
    ///
    /// 支持Suricata/Snort风格的规则格式，包括多行规则。
    /// 包含详细的调试日志，专门处理9010000系列规则。
    ///
    /// # 参数
    /// * `content` - Hyperscan格式的规则内容
    ///
    /// # 返回值
    /// * `Result<u32>` - 成功返回解析的规则数量，失败返回错误
    fn parse_hyperscan_rules(&mut self, content: &str) -> Result<u32> {
        let mut loaded_count = 0;
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        log::debug!("🔍 开始解析Hyperscan规则文件，共{}行", lines.len());

        while i < lines.len() {
            let line = lines[i].trim();

            // 跳过空行和注释行
            if line.is_empty() || line.starts_with('#') {
                i += 1;
                continue;
            }

            // 检查是否是规则开始（action protocol ...）
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 7 { // 最小规则格式：alert http any -> any any (msg:"test"; sid:1;)
                i += 1;
                continue;
            }

            let action_str = parts[0];
            let protocol = parts[1];

            log::debug!("🔍 Rule parsing: line {} = '{}' (len: {})", i + 1, line, line.len());
            log::debug!("   -> action_str: '{}' | protocol: '{}'", action_str, protocol);
            log::debug!("   -> parts count: {}", parts.len());

            // 检查是否是有效的HTTP规则动作
            if !matches!(action_str, "alert" | "drop" | "reset" | "pass") {
                log::debug!("   -> 跳过非HTTP规则动作: {}", action_str);
                i += 1;
                continue;
            }

            // 只处理HTTP规则
            if protocol != "http" {
                log::debug!("   -> 跳过非HTTP协议: {}", protocol);
                i += 1;
                continue;
            }

            // 检查是否包含sid字段（基本验证）
            if !line.contains("sid:") {
                log::warn!("⚠️  规则缺少sid字段，行 {}: {}", i + 1, line);
                i += 1;
                continue;
            }

            // 特别检查9010000系列规则
            let is_9010000_series = line.contains("sid:901000");
            if is_9010000_series {
                log::debug!("🎯 发现9010000系列规则在行 {}: {}", i + 1, line);

                // 提取SID进行详细分析
                if let Some(sid_start) = line.find("sid:") {
                    if let Some(sid_end) = line[sid_start + 4..].find(';') {
                        let sid_str = line[sid_start + 4..sid_start + 4 + sid_end].trim();
                        if let Ok(sid_num) = sid_str.parse::<u32>() {
                            log::debug!("   -> 提取到SID: {}", sid_num);

                            if sid_num >= 9010001 && sid_num <= 9010010 {
                                log::debug!("✅ 确认为9010000系列规则: SID={}", sid_num);

                                // 分析规则特性
                                if line.contains("http.method") {
                                    log::debug!("   -> 包含http.method检测");
                                }
                                if line.contains("content:") {
                                    log::debug!("   -> 包含content模式");
                                }
                                if line.contains("nocase") {
                                    log::debug!("   -> 包含nocase修饰符");
                                }
                                if line.contains("pcre:") {
                                    log::debug!("   -> 包含PCRE模式");
                                }
                            }
                        } else {
                            log::warn!("⚠️  SID解析失败: '{}'", sid_str);
                        }
                    }
                }
            }

            log::debug!("✅ HTTP rule accepted: '{}'", line);

            // 合并多行规则
            let mut rule_text = line.to_string();
            let start_line_num = i + 1;
            let mut paren_depth = 0;
            let mut in_string = false;
            let mut escape_next = false;

            // 计算当前行的括号深度
            for ch in line.chars() {
                if escape_next {
                    escape_next = false;
                    continue;
                }
                match ch {
                    '\\' => escape_next = true,
                    '"' => in_string = !in_string,
                    '(' if !in_string => paren_depth += 1,
                    ')' if !in_string => {
                        paren_depth -= 1;
                        if paren_depth < 0 {
                            break; // 多余的右括号，可能是错误
                        }
                    }
                    _ => {}
                }
            }

            // 如果括号未匹配，继续读取后续行
            i += 1;
            while paren_depth > 0 && i < lines.len() {
                let next_line = lines[i].trim();

                // 跳过空行（但在规则中间不应该有注释）
                if next_line.is_empty() {
                    rule_text.push(' '); // 保留空格
                    i += 1;
                    continue;
                }

                // 规则中间的注释行，跳过但保持空格
                if next_line.starts_with('#') {
                    rule_text.push(' ');
                    i += 1;
                    continue;
                }

                // 追加到规则文本
                rule_text.push(' ');
                rule_text.push_str(next_line);

                // 更新括号深度
                for ch in next_line.chars() {
                    if escape_next {
                        escape_next = false;
                        continue;
                    }
                    match ch {
                        '\\' => escape_next = true,
                        '"' => in_string = !in_string,
                        '(' if !in_string => paren_depth += 1,
                        ')' if !in_string => {
                            paren_depth -= 1;
                            if paren_depth == 0 {
                                break; // 找到匹配的右括号
                            }
                        }
                        _ => {}
                    }
                }

                i += 1;
            }

            // 如果括号仍未匹配，记录警告但继续
            if paren_depth != 0 {
                log::warn!("⚠️  括号不匹配，规则起始行: {}", start_line_num);
                continue;
            }

            log::debug!("🔍 解析完整规则文本: {}", rule_text);

            // 解析合并后的规则
            match self.parse_suricata_rule(&rule_text, start_line_num) {
                Ok(rule) => {
                    log::debug!("✅ 规则解析成功: SID={}, 动作={:?}, 模式数={}",
                              rule.id, rule.action, rule.patterns.len());

                    // 如果是9010000系列规则，进行详细验证
                    if is_9010000_series {
                        log::debug!("🎯 9010000系列规则解析详情:");
                        log::debug!("   -> SID: {}", rule.id);
                        log::debug!("   -> 消息: {}", rule.message);
                        log::debug!("   -> 模式数量: {}", rule.patterns.len());

                        for (pattern_idx, pattern) in rule.patterns.iter().enumerate() {
                            log::debug!("   -> 模式{}: '{}' (位置: {:?}, 大小写: {}, Fast: {})",
                                       pattern_idx, pattern.pattern, pattern.http_location,
                                       pattern.nocase, pattern.is_fast_pattern);
                        }

                        if rule.id >= 9010001 && rule.id <= 9010010 {
                            log::debug!("✅ 9010000系列规则验证通过: SID={}", rule.id);
                        } else {
                            log::warn!("⚠️  9010000系列规则ID超出预期范围: SID={}", rule.id);
                        }
                    }

                    // 尝试添加规则到管理器
                    match self.add_rule(rule) {
                        Ok(_) => {
                            loaded_count += 1;
                            if is_9010000_series {
                                log::debug!("✅ 9010000系列规则成功添加到引擎");
                            }
                        }
                        Err(e) => {
                            log::warn!("❌ 规则添加失败，行 {}: {}", start_line_num, e);
                            if is_9010000_series {
                                log::error!("🚨 9010000系列规则添加失败: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!("❌ 规则解析失败，行 {}: {}", start_line_num, e);
                    if is_9010000_series {
                        log::error!("🚨 9010000系列规则解析失败: {}", e);
                    }
                }
            }
        }

        log::debug!("🔍 Hyperscan规则解析完成，成功加载{}条规则", loaded_count);
        Ok(loaded_count)
    }