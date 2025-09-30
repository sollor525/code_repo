use iced::{Element, Length};
use iced::widget::{button, checkbox, column, container, row, scrollable, text, text_input};
use hyperscan::prelude::*;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub enum Message {
    RegexPatternChanged(String),
    TestStringChanged(String),
    CaseSensitiveToggled(bool),
    MultiLineToggled(bool),
    DotAllToggled(bool),
    PerformMatch,
    ClearResults,
}

pub struct RegexMatcher {
    regex_pattern: String,
    test_string: String,
    match_result: String,
    is_case_sensitive: bool,
    is_multi_line: bool,
    is_dot_all: bool,
}

impl RegexMatcher {
    pub fn new() -> Self {
        Self {
            regex_pattern: String::new(),
            test_string: String::new(),
            match_result: String::new(),
            is_case_sensitive: true,
            is_multi_line: false,
            is_dot_all: false,
        }
    }
    
    pub fn update(&mut self, message: Message) {
        match message {
            Message::RegexPatternChanged(value) => self.regex_pattern = value,
            Message::TestStringChanged(value) => self.test_string = value,
            Message::CaseSensitiveToggled(value) => self.is_case_sensitive = value,
            Message::MultiLineToggled(value) => self.is_multi_line = value,
            Message::DotAllToggled(value) => self.is_dot_all = value,
            Message::PerformMatch => self.perform_match(),
            Message::ClearResults => self.match_result.clear(),
        }
    }
    
    pub fn view(&self) -> Element<Message> {
        let title = text("正则表达式匹配工具").size(24);
        
        let regex_pattern_input = column![
            text("正则表达式模式:").size(16),
            text_input("输入正则表达式...", &self.regex_pattern)
                .on_input(Message::RegexPatternChanged)
                .padding(10)
        ].spacing(5);
        
        let checkboxes = row![
            checkbox("区分大小写", self.is_case_sensitive)
                .on_toggle(Message::CaseSensitiveToggled),
            checkbox("多行模式", self.is_multi_line)
                .on_toggle(Message::MultiLineToggled),
            checkbox("点号匹配所有字符", self.is_dot_all)
                .on_toggle(Message::DotAllToggled)
        ].spacing(20);
        
        let test_string_input = column![
            text("测试文本:").size(16),
            text_input("输入测试文本...", &self.test_string)
                .on_input(Message::TestStringChanged)
                .padding(10)
                .height(Length::Units(150))
        ].spacing(5);
        
        let buttons = row![
            button("匹配").on_press(Message::PerformMatch),
            button("清除").on_press(Message::ClearResults)
        ].spacing(10);
        
        let results = column![
            text("匹配结果:").size(16),
            scrollable(
                container(
                    text(&self.match_result).size(14)
                ).padding(10)
            ).height(Length::Units(200))
        ].spacing(5);
        
        column![
            title,
            regex_pattern_input,
            checkboxes,
            test_string_input,
            buttons,
            results
        ].spacing(20).padding(20).into()
    }
    
    fn perform_match(&mut self) {
        if self.regex_pattern.is_empty() || self.test_string.is_empty() {
            self.match_result = "请输入正则表达式和测试文本".to_string();
            return;
        }
        
        // 清除之前的结果
        self.match_result.clear();
        
        // 设置Hyperscan标志
        let mut flags = PatternFlags::empty();
        if !self.is_case_sensitive {
            flags |= PatternFlags::CASELESS;
        }
        if self.is_multi_line {
            flags |= PatternFlags::MULTILINE;
        }
        if self.is_dot_all {
            flags |= PatternFlags::DOTALL;
        }
        
        // 创建匹配结果容器
        let matches = Arc::new(Mutex::new(Vec::new()));
        
        // 创建匹配回调函数
        let matches_clone = matches.clone();
        let event_handler = move |id: u32, from: u64, to: u64, _flags: u32| {
            let mut matches = matches_clone.lock().unwrap();
            matches.push((id, from, to));
            Matching::Continue
        };
        
        // 构建Hyperscan数据库
        let pattern = Pattern::new(&self.regex_pattern, flags);
        match pattern {
            Ok(pattern) => {
                let builder = BlockDatabase::builder();
                match builder.add_pattern(&pattern) {
                    Ok(builder) => {
                        match builder.build() {
                            Ok(database) => {
                                // 执行匹配
                                let scratch = database.alloc_scratch().unwrap();
                                let result = database.scan(
                                    self.test_string.as_bytes(),
                                    &scratch,
                                    event_handler
                                );
                                
                                match result {
                                    Ok(_) => {
                                        let matches = matches.lock().unwrap();
                                        if matches.is_empty() {
                                            self.match_result = "没有找到匹配项".to_string();
                                        } else {
                                            self.match_result = format!("找到 {} 个匹配项:\n", matches.len());
                                            for (i, &(_, from, to)) in matches.iter().enumerate() {
                                                let matched_text = &self.test_string[from as usize..to as usize];
                                                self.match_result.push_str(&format!("{}. 位置 {}-{}: '{}'\n", 
                                                    i+1, from, to, matched_text));
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        self.match_result = format!("匹配过程中出错: {}", e);
                                    }
                                }
                            },
                            Err(e) => {
                                self.match_result = format!("构建数据库失败: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        self.match_result = format!("添加模式失败: {}", e);
                    }
                }
            },
            Err(e) => {
                self.match_result = format!("无效的正则表达式: {}", e);
            }
        }
    }
}