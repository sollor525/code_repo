use regex;

pub struct RegexMatcher {
    regex_pattern: String,
    test_string: String,
    is_case_sensitive: bool,
    is_multi_line: bool,
    is_dot_all: bool,
}

pub type MatchResults = Vec<((usize, usize), String, Vec<String>)>;

impl RegexMatcher {
    pub fn new() -> Self {
        Self {
            regex_pattern: String::new(),
            test_string: String::new(),
            is_case_sensitive: true,
            is_multi_line: false,
            is_dot_all: false,
        }
    }

    pub fn set_pattern(&mut self, pattern: &str) {
        self.regex_pattern = pattern.to_string();
    }

    pub fn set_test_string(&mut self, test_string: &str) {
        self.test_string = test_string.to_string();
    }

    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.is_case_sensitive = case_sensitive;
    }

    pub fn set_multi_line(&mut self, multi_line: bool) {
        self.is_multi_line = multi_line;
    }

    pub fn set_dot_all(&mut self, dot_all: bool) {
        self.is_dot_all = dot_all;
    }

    pub fn perform_match(&self) -> MatchResults {
        if self.regex_pattern.is_empty() || self.test_string.is_empty() {
            return Vec::new();
        }

        // 构建正则表达式选项
        let mut regex_options = regex::RegexBuilder::new(&self.regex_pattern);

        if !self.is_case_sensitive {
            regex_options.case_insensitive(true);
        }

        if self.is_multi_line {
            regex_options.multi_line(true);
        }

        // 注意：标准 regex 库没有直接的 dotAll 选项，但可以通过 (?s) 标志实现
        let pattern_to_use = if self.is_dot_all {
            // 在模式前面添加 (?s) 标志来启用 dotAll 模式
            format!("(?s){}", self.regex_pattern)
        } else {
            self.regex_pattern.clone()
        };

        let mut regex_options = regex::RegexBuilder::new(&pattern_to_use);
        if !self.is_case_sensitive {
            regex_options.case_insensitive(true);
        }
        if self.is_multi_line {
            regex_options.multi_line(true);
        }

        // 编译正则表达式
        match regex_options.build() {
            Ok(regex) => {
                // 查找所有匹配项
                let matches: Vec<_> = regex.find_iter(&self.test_string).collect();

                let mut results = Vec::new();

                for m in matches.iter() {
                    let matched_text = m.as_str();
                    let start = m.start();
                    let end = m.end();

                    // 如果有捕获组，也显示捕获组
                    let groups = if let Some(captures) = regex.captures(m.as_str()) {
                        captures.iter()
                            .skip(1) // 跳过第0个组（整个匹配）
                            .filter_map(|group| group.map(|g| g.as_str().to_string()))
                            .collect()
                    } else {
                        Vec::new()
                    };

                    results.push(((start, end), matched_text.to_string(), groups));
                }

                results
            },
            Err(_) => {
                Vec::new()
            }
        }
    }
}