//! JSON 工具：格式化（美化 / 压缩 / 排序键 / 转义非 ASCII）与字段搜索。
//!
//! 基于 `serde_json`，并开启 `preserve_order`（保留原始键顺序，排序改为显式选项）
//! 与 `arbitrary_precision`（原样保留数字字面量，避免大整数/长小数被 f64 截断）。
//!
//! 搜索支持四种模式：
//! - `key` / `value` / `any`：按键名、标量值、或两者做包含/精确匹配（可区分大小写）；
//! - `path`：JSONPath 简版，支持 `$`、`.name`、`["name"]`、`[n]`（含负下标）、
//!   `[*]` / `.*` 通配、`..name` 递归下降、`..*` 递归全部。
//!   不支持过滤表达式 `[?(...)]` 与切片 `[a:b]`。

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// 单条搜索结果中值预览的最大字符数
const PREVIEW_CHARS: usize = 160;

// =============================  DTO  =============================

fn default_pretty() -> String {
    "pretty".to_string()
}
fn default_any() -> String {
    "any".to_string()
}
fn default_indent() -> usize {
    2
}
fn default_limit() -> usize {
    200
}

#[derive(Deserialize)]
pub struct JsonFormatRequest {
    pub input: String,
    /// pretty | minify
    #[serde(default = "default_pretty")]
    pub mode: String,
    /// 缩进空格数（1-8），`use_tabs` 为真时忽略
    #[serde(default = "default_indent")]
    pub indent: usize,
    #[serde(default)]
    pub use_tabs: bool,
    /// 递归按字典序排序对象的键
    #[serde(default)]
    pub sort_keys: bool,
    /// 把非 ASCII 字符转义为 \uXXXX
    #[serde(default)]
    pub escape_unicode: bool,
}

#[derive(Serialize, Debug)]
pub struct JsonStats {
    pub nodes: usize,
    pub objects: usize,
    pub arrays: usize,
    pub keys: usize,
    pub strings: usize,
    pub numbers: usize,
    pub booleans: usize,
    pub nulls: usize,
    pub max_depth: usize,
}

#[derive(Serialize, Debug)]
pub struct JsonFormatResponse {
    pub result: String,
    pub mode: String,
    pub original_size: usize,
    pub result_size: usize,
    pub stats: JsonStats,
}

#[derive(Deserialize)]
pub struct JsonSearchRequest {
    pub input: String,
    pub query: String,
    /// key | value | any | path
    #[serde(default = "default_any")]
    pub mode: String,
    #[serde(default)]
    pub case_sensitive: bool,
    /// 精确匹配（默认为包含匹配）；`path` 模式下无效
    #[serde(default)]
    pub exact: bool,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

#[derive(Serialize, Debug)]
pub struct JsonMatch {
    /// 形如 `$.store.book[0].title`
    pub path: String,
    pub key: Option<String>,
    pub value_type: String,
    /// 值预览（过长会截断）
    pub value: String,
    /// 命中位置：键 / 值 / 键和值 / 路径
    pub matched_on: String,
}

#[derive(Serialize, Debug)]
pub struct JsonSearchResponse {
    pub mode: String,
    pub query: String,
    pub total: usize,
    pub returned: usize,
    pub truncated: bool,
    pub matches: Vec<JsonMatch>,
}

// =============================  解析  =============================

fn parse(input: &str) -> Result<Value, String> {
    if input.trim().is_empty() {
        return Err("请输入 JSON 内容".to_string());
    }
    serde_json::from_str(input).map_err(|e| {
        let raw = e.to_string();
        // serde_json 的消息尾部带英文 " at line X column Y"，剥离后换成中文定位
        let msg = raw.split(" at line ").next().unwrap_or(&raw);
        format!("JSON 解析失败（第 {} 行，第 {} 列）：{}", e.line(), e.column(), msg)
    })
}

// =============================  格式化  =============================

/// 递归按字典序排序对象的键（数组元素顺序不变）
fn sort_value(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = Map::new();
            for (k, mut child) in entries {
                sort_value(&mut child);
                sorted.insert(k, child);
            }
            *map = sorted;
        }
        Value::Array(arr) => arr.iter_mut().for_each(sort_value),
        _ => {}
    }
}

/// 把非 ASCII 字符转义为 `\uXXXX`（BMP 外用代理对）。
///
/// 在 serde_json 的输出里，非 ASCII 字符只可能出现在字符串字面量内部
/// （结构字符与数字都是 ASCII），因此逐字符替换是安全的。
fn escape_non_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut buf = [0u16; 2];
            for unit in c.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

fn to_pretty(value: &Value, indent: &[u8]) -> Result<String, String> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(indent);
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value
        .serialize(&mut ser)
        .map_err(|e| format!("序列化失败：{e}"))?;
    String::from_utf8(buf).map_err(|e| format!("序列化结果非 UTF-8：{e}"))
}

// =============================  统计  =============================

fn collect_stats(v: &Value, depth: usize, st: &mut JsonStats) {
    st.nodes += 1;
    st.max_depth = st.max_depth.max(depth);
    match v {
        Value::Object(m) => {
            st.objects += 1;
            st.keys += m.len();
            for (_, child) in m {
                collect_stats(child, depth + 1, st);
            }
        }
        Value::Array(a) => {
            st.arrays += 1;
            for child in a {
                collect_stats(child, depth + 1, st);
            }
        }
        Value::String(_) => st.strings += 1,
        Value::Number(_) => st.numbers += 1,
        Value::Bool(_) => st.booleans += 1,
        Value::Null => st.nulls += 1,
    }
}

fn stats_of(v: &Value) -> JsonStats {
    let mut st = JsonStats {
        nodes: 0,
        objects: 0,
        arrays: 0,
        keys: 0,
        strings: 0,
        numbers: 0,
        booleans: 0,
        nulls: 0,
        max_depth: 0,
    };
    collect_stats(v, 1, &mut st);
    st
}

// =============================  路径与预览  =============================

fn is_simple_ident(k: &str) -> bool {
    let mut chars = k.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn append_key(path: &str, k: &str) -> String {
    if is_simple_ident(k) {
        format!("{path}.{k}")
    } else {
        let quoted = serde_json::to_string(k).unwrap_or_else(|_| format!("\"{k}\""));
        format!("{path}[{quoted}]")
    }
}

fn append_index(path: &str, i: usize) -> String {
    format!("{path}[{i}]")
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Object(_) => "对象",
        Value::Array(_) => "数组",
        Value::String(_) => "字符串",
        Value::Number(_) => "数字",
        Value::Bool(_) => "布尔",
        Value::Null => "空",
    }
}

/// 标量值的可比较文本；容器返回 None
fn scalar_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some("null".to_string()),
        _ => None,
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn preview(v: &Value) -> String {
    let s = match v {
        // 字符串直接展示内容，不再套一层引号
        Value::String(s) => s.clone(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    };
    truncate_chars(&s, PREVIEW_CHARS)
}

// =============================  JSONPath 简版  =============================

enum Sel {
    Key(String),
    Index(i64),
    Wildcard,
    /// `..name`
    Descend(String),
    /// `..*`
    DescendAny,
}

fn read_name(s: &[char], i: &mut usize) -> String {
    let start = *i;
    while *i < s.len() && s[*i] != '.' && s[*i] != '[' {
        *i += 1;
    }
    s[start..*i].iter().collect()
}

fn parse_path(query: &str) -> Result<Vec<Sel>, String> {
    let s: Vec<char> = query.trim().chars().collect();
    let mut sels: Vec<Sel> = Vec::new();
    let mut i = 0usize;

    if i < s.len() && s[i] == '$' {
        i += 1;
    }

    while i < s.len() {
        match s[i] {
            '.' => {
                if i + 1 < s.len() && s[i + 1] == '.' {
                    i += 2;
                    if i < s.len() && s[i] == '*' {
                        sels.push(Sel::DescendAny);
                        i += 1;
                    } else {
                        let name = read_name(&s, &mut i);
                        if name.is_empty() {
                            return Err("`..` 之后需要跟字段名或 `*`".to_string());
                        }
                        sels.push(Sel::Descend(name));
                    }
                } else {
                    i += 1;
                    if i < s.len() && s[i] == '*' {
                        sels.push(Sel::Wildcard);
                        i += 1;
                    } else {
                        let name = read_name(&s, &mut i);
                        if name.is_empty() {
                            return Err("`.` 之后需要跟字段名或 `*`".to_string());
                        }
                        sels.push(Sel::Key(name));
                    }
                }
            }
            '[' => {
                i += 1;
                // 带引号的字段名，允许其中含 `]`
                if i < s.len() && (s[i] == '\'' || s[i] == '"') {
                    let quote = s[i];
                    i += 1;
                    let mut name = String::new();
                    while i < s.len() && s[i] != quote {
                        name.push(s[i]);
                        i += 1;
                    }
                    if i >= s.len() {
                        return Err("路径中的引号未闭合".to_string());
                    }
                    i += 1; // 跳过收尾引号
                    if i >= s.len() || s[i] != ']' {
                        return Err("路径中的 `[` 未正确闭合".to_string());
                    }
                    i += 1;
                    sels.push(Sel::Key(name));
                    continue;
                }
                let mut inner = String::new();
                let mut closed = false;
                while i < s.len() {
                    if s[i] == ']' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    inner.push(s[i]);
                    i += 1;
                }
                if !closed {
                    return Err("路径中的 `[` 未闭合".to_string());
                }
                let t = inner.trim();
                if t == "*" {
                    sels.push(Sel::Wildcard);
                } else if let Ok(n) = t.parse::<i64>() {
                    sels.push(Sel::Index(n));
                } else {
                    return Err(format!(
                        "无效的下标「{t}」：应为整数、`*` 或带引号的字段名"
                    ));
                }
            }
            // 允许省略开头的 `$.`，例如 `store.book[0]`
            c if sels.is_empty() => {
                let name = read_name(&s, &mut i);
                if name.is_empty() {
                    return Err(format!("路径中出现意外字符「{c}」"));
                }
                sels.push(Sel::Key(name));
            }
            c => return Err(format!("路径中出现意外字符「{c}」")),
        }
    }
    Ok(sels)
}

/// 递归下降：收集所有键名为 `key` 的成员
fn collect_descend<'a>(path: &str, v: &'a Value, key: &str, out: &mut Vec<(String, &'a Value)>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                let cp = append_key(path, k);
                if k == key {
                    out.push((cp.clone(), child));
                }
                collect_descend(&cp, child, key, out);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                collect_descend(&append_index(path, i), child, key, out);
            }
        }
        _ => {}
    }
}

/// 递归下降：收集所有后代节点
fn collect_descend_any<'a>(path: &str, v: &'a Value, out: &mut Vec<(String, &'a Value)>) {
    match v {
        Value::Object(m) => {
            for (k, child) in m {
                let cp = append_key(path, k);
                out.push((cp.clone(), child));
                collect_descend_any(&cp, child, out);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                let cp = append_index(path, i);
                out.push((cp.clone(), child));
                collect_descend_any(&cp, child, out);
            }
        }
        _ => {}
    }
}

fn eval_path<'a>(root: &'a Value, sels: &[Sel]) -> Vec<(String, &'a Value)> {
    let mut cur: Vec<(String, &Value)> = vec![("$".to_string(), root)];
    for sel in sels {
        let mut next: Vec<(String, &Value)> = Vec::new();
        for (path, v) in &cur {
            match sel {
                Sel::Key(k) => {
                    if let Some(child) = v.as_object().and_then(|o| o.get(k)) {
                        next.push((append_key(path, k), child));
                    }
                }
                Sel::Index(n) => {
                    if let Some(arr) = v.as_array() {
                        let idx = if *n < 0 { arr.len() as i64 + n } else { *n };
                        if idx >= 0 && (idx as usize) < arr.len() {
                            let u = idx as usize;
                            next.push((append_index(path, u), &arr[u]));
                        }
                    }
                }
                Sel::Wildcard => match v {
                    Value::Object(m) => {
                        for (k, child) in m {
                            next.push((append_key(path, k), child));
                        }
                    }
                    Value::Array(a) => {
                        for (i, child) in a.iter().enumerate() {
                            next.push((append_index(path, i), child));
                        }
                    }
                    _ => {}
                },
                Sel::Descend(k) => collect_descend(path, v, k, &mut next),
                Sel::DescendAny => collect_descend_any(path, v, &mut next),
            }
        }
        cur = next;
    }
    cur
}

// =============================  键 / 值搜索  =============================

struct SearchCtx {
    query: String,
    case_sensitive: bool,
    exact: bool,
    check_key: bool,
    check_value: bool,
}

impl SearchCtx {
    fn matches(&self, hay: &str) -> bool {
        if self.case_sensitive {
            if self.exact {
                hay == self.query
            } else {
                hay.contains(&self.query)
            }
        } else {
            let h = hay.to_lowercase();
            let n = self.query.to_lowercase();
            if self.exact {
                h == n
            } else {
                h.contains(&n)
            }
        }
    }
}

fn walk(v: &Value, path: String, key: Option<&str>, ctx: &SearchCtx, out: &mut Vec<JsonMatch>) {
    let key_hit = ctx.check_key && key.is_some_and(|k| ctx.matches(k));
    let val_hit = ctx.check_value && scalar_string(v).is_some_and(|s| ctx.matches(&s));

    if key_hit || val_hit {
        let matched_on = if key_hit && val_hit {
            "键和值"
        } else if key_hit {
            "键"
        } else {
            "值"
        };
        out.push(JsonMatch {
            path: path.clone(),
            key: key.map(str::to_string),
            value_type: type_name(v).to_string(),
            value: preview(v),
            matched_on: matched_on.to_string(),
        });
    }

    match v {
        Value::Object(m) => {
            for (k, child) in m {
                walk(child, append_key(&path, k), Some(k), ctx, out);
            }
        }
        Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                walk(child, append_index(&path, i), None, ctx, out);
            }
        }
        _ => {}
    }
}

// =============================  对外接口  =============================

pub fn format(req: &JsonFormatRequest) -> Result<JsonFormatResponse, String> {
    let mut value = parse(&req.input)?;
    if req.sort_keys {
        sort_value(&mut value);
    }
    let stats = stats_of(&value);

    let mut result = match req.mode.as_str() {
        "minify" => serde_json::to_string(&value).map_err(|e| format!("序列化失败：{e}"))?,
        "pretty" => {
            let indent: Vec<u8> = if req.use_tabs {
                vec![b'\t']
            } else {
                vec![b' '; req.indent.clamp(1, 8)]
            };
            to_pretty(&value, &indent)?
        }
        other => return Err(format!("未知的格式化模式：{other}")),
    };
    if req.escape_unicode {
        result = escape_non_ascii(&result);
    }

    Ok(JsonFormatResponse {
        mode: req.mode.clone(),
        original_size: req.input.len(),
        result_size: result.len(),
        result,
        stats,
    })
}

pub fn search(req: &JsonSearchRequest) -> Result<JsonSearchResponse, String> {
    let root = parse(&req.input)?;
    let limit = req.limit.clamp(1, 1000);

    let mut matches: Vec<JsonMatch> = Vec::new();
    match req.mode.as_str() {
        "path" => {
            let sels = parse_path(&req.query)?;
            for (path, v) in eval_path(&root, &sels) {
                matches.push(JsonMatch {
                    path,
                    key: None,
                    value_type: type_name(v).to_string(),
                    value: preview(v),
                    matched_on: "路径".to_string(),
                });
            }
        }
        mode @ ("key" | "value" | "any") => {
            if req.query.is_empty() {
                return Err("请输入搜索关键字".to_string());
            }
            let ctx = SearchCtx {
                query: req.query.clone(),
                case_sensitive: req.case_sensitive,
                exact: req.exact,
                check_key: mode != "value",
                check_value: mode != "key",
            };
            walk(&root, "$".to_string(), None, &ctx, &mut matches);
        }
        other => return Err(format!("未知的搜索模式：{other}")),
    }

    let total = matches.len();
    let truncated = total > limit;
    matches.truncate(limit);

    Ok(JsonSearchResponse {
        mode: req.mode.clone(),
        query: req.query.clone(),
        total,
        returned: matches.len(),
        truncated,
        matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "store": {
            "book": [
                {"title": "Rust 编程", "price": 59.9, "tags": ["sys", "rust"]},
                {"title": "Go 编程", "price": 45, "tags": ["sys", "go"]}
            ],
            "bicycle": {"color": "red", "price": 199}
        },
        "expensive": 10
    }"#;

    fn fmt_req(input: &str) -> JsonFormatRequest {
        JsonFormatRequest {
            input: input.to_string(),
            mode: "pretty".to_string(),
            indent: 2,
            use_tabs: false,
            sort_keys: false,
            escape_unicode: false,
        }
    }

    fn search_req(query: &str, mode: &str) -> JsonSearchRequest {
        JsonSearchRequest {
            input: SAMPLE.to_string(),
            query: query.to_string(),
            mode: mode.to_string(),
            case_sensitive: false,
            exact: false,
            limit: 200,
        }
    }

    #[test]
    fn pretty_uses_requested_indent() {
        let mut r = fmt_req(r#"{"a":1}"#);
        assert_eq!(format(&r).unwrap().result, "{\n  \"a\": 1\n}");
        r.indent = 4;
        assert_eq!(format(&r).unwrap().result, "{\n    \"a\": 1\n}");
        r.use_tabs = true;
        assert_eq!(format(&r).unwrap().result, "{\n\t\"a\": 1\n}");
    }

    #[test]
    fn minify_strips_whitespace() {
        let mut r = fmt_req("{\n  \"a\" : [1, 2] \n}");
        r.mode = "minify".to_string();
        let out = format(&r).unwrap();
        assert_eq!(out.result, r#"{"a":[1,2]}"#);
        assert!(out.result_size < out.original_size);
    }

    #[test]
    fn key_order_is_preserved_unless_sorting_is_requested() {
        let mut r = fmt_req(r#"{"z":1,"a":2,"m":3}"#);
        r.mode = "minify".to_string();
        assert_eq!(format(&r).unwrap().result, r#"{"z":1,"a":2,"m":3}"#);
        r.sort_keys = true;
        assert_eq!(format(&r).unwrap().result, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn sorting_is_recursive() {
        let mut r = fmt_req(r#"{"b":{"y":1,"x":2},"a":[{"q":1,"p":2}]}"#);
        r.mode = "minify".to_string();
        r.sort_keys = true;
        assert_eq!(
            format(&r).unwrap().result,
            r#"{"a":[{"p":2,"q":1}],"b":{"x":2,"y":1}}"#
        );
    }

    #[test]
    fn number_literals_survive_round_trip() {
        // 大整数超出 f64 精度、长小数都应原样保留（指数写法会补上 `+` 号，值不变）
        let mut r = fmt_req(r#"{"id":9223372036854775808,"pi":3.14159265358979311600,"e":1e400}"#);
        r.mode = "minify".to_string();
        assert_eq!(
            format(&r).unwrap().result,
            r#"{"id":9223372036854775808,"pi":3.14159265358979311600,"e":1e+400}"#
        );
    }

    #[test]
    fn escape_unicode_only_touches_non_ascii() {
        let mut r = fmt_req(r#"{"名":"值","ascii":"a\"b"}"#);
        r.mode = "minify".to_string();
        r.escape_unicode = true;
        let out = format(&r).unwrap().result;
        // 输出应为纯 ASCII，两个中文字符各转义成一个 \uXXXX
        let esc = format!("{}u", '\\');
        assert!(out.is_ascii(), "{out}");
        assert_eq!(out.matches(&esc).count(), 2, "{out}");
        // ASCII 部分（含已转义的引号）原样保留
        assert!(out.contains(r#""ascii":"a\"b""#), "{out}");
        // 转义后仍是合法 JSON，且解析回来内容不变
        let back: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(back["名"], Value::String("值".to_string()));
    }

    #[test]
    fn escape_unicode_uses_surrogate_pairs_beyond_bmp() {
        let mut r = fmt_req(r#"{"emoji":"😀"}"#);
        r.mode = "minify".to_string();
        r.escape_unicode = true;
        let out = format(&r).unwrap().result;
        // U+1F600 在 BMP 之外，需拆成一对代理项 → 两个 \uXXXX
        let esc = format!("{}u", '\\');
        assert!(out.is_ascii(), "{out}");
        assert_eq!(out.matches(&esc).count(), 2, "{out}");
        // 代理对能被正确解析回原字符，说明拆分方向正确
        let back: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(back["emoji"], Value::String("😀".to_string()));
    }

    #[test]
    fn parse_error_reports_line_and_column() {
        let r = fmt_req("{\n  \"a\": ,\n}");
        let err = format(&r).unwrap_err();
        assert!(err.contains("第 2 行"), "{err}");
        assert!(!err.contains("at line"), "英文定位后缀应被剥离：{err}");
    }

    #[test]
    fn stats_describe_the_document() {
        let r = fmt_req(SAMPLE);
        let st = format(&r).unwrap().stats;
        assert_eq!(st.objects, 5); // 根 + store + 2 本书 + bicycle
        assert_eq!(st.arrays, 3); // book + 两个 tags
        assert_eq!(st.strings, 7); // 2 个 title + 4 个 tag + color
        assert_eq!(st.numbers, 4); // 2 个书价 + bicycle.price + expensive
        assert_eq!(st.max_depth, 6); // 根 → store → book → book[0] → tags → "sys"
    }

    #[test]
    fn search_by_key_finds_nested_matches() {
        let r = search(&search_req("price", "key")).unwrap();
        assert_eq!(r.total, 3);
        assert!(r.matches.iter().all(|m| m.matched_on == "键"));
        assert!(r.matches.iter().any(|m| m.path == "$.store.book[0].price"));
        assert!(r.matches.iter().any(|m| m.path == "$.store.bicycle.price"));
    }

    #[test]
    fn search_by_value_matches_scalars_of_any_type() {
        let r = search(&search_req("59.9", "value")).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].path, "$.store.book[0].price");
        assert_eq!(r.matches[0].value_type, "数字");

        // 包含匹配下 "rust" 也会命中标题 "Rust 编程"（不区分大小写）
        let r = search(&search_req("rust", "value")).unwrap();
        assert_eq!(r.total, 2);
        assert!(r.matches.iter().any(|m| m.path == "$.store.book[0].title"));

        // 精确匹配只留下 tags 里的那个；数组元素没有键名，但路径带下标
        let mut req = search_req("rust", "value");
        req.exact = true;
        let r = search(&req).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].path, "$.store.book[0].tags[1]");
        assert!(r.matches[0].key.is_none());
    }

    #[test]
    fn search_any_reports_key_and_value_hit_once() {
        // "red" 只作为值出现
        let r = search(&search_req("red", "any")).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].matched_on, "值");

        // 键与值同时命中时合并为一条
        let req = JsonSearchRequest {
            input: r#"{"color":"colorful"}"#.to_string(),
            query: "color".to_string(),
            mode: "any".to_string(),
            case_sensitive: false,
            exact: false,
            limit: 200,
        };
        let r = search(&req).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].matched_on, "键和值");
    }

    #[test]
    fn search_honours_case_sensitivity_and_exact_match() {
        let mut req = search_req("PRICE", "key");
        assert_eq!(search(&req).unwrap().total, 3);
        req.case_sensitive = true;
        assert_eq!(search(&req).unwrap().total, 0);

        let mut req = search_req("pric", "key");
        assert_eq!(search(&req).unwrap().total, 3); // 包含匹配
        req.exact = true;
        assert_eq!(search(&req).unwrap().total, 0); // 精确匹配
    }

    #[test]
    fn search_truncates_at_limit() {
        let mut req = search_req("price", "key");
        req.limit = 2;
        let r = search(&req).unwrap();
        assert_eq!(r.total, 3);
        assert_eq!(r.returned, 2);
        assert!(r.truncated);
    }

    #[test]
    fn path_child_index_and_wildcard() {
        let r = search(&search_req("$.store.book[0].title", "path")).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].value, "Rust 编程");

        // 通配所有书的 title
        let r = search(&search_req("$.store.book[*].title", "path")).unwrap();
        assert_eq!(r.total, 2);

        // 负下标取最后一个
        let r = search(&search_req("$.store.book[-1].title", "path")).unwrap();
        assert_eq!(r.matches[0].value, "Go 编程");
    }

    #[test]
    fn path_recursive_descent_and_bracket_names() {
        let r = search(&search_req("$..price", "path")).unwrap();
        assert_eq!(r.total, 3);

        let r = search(&search_req(r#"$["store"]["bicycle"]["color"]"#, "path")).unwrap();
        assert_eq!(r.matches[0].value, "red");

        // 省略开头的 $. 也可
        let r = search(&search_req("store.bicycle.color", "path")).unwrap();
        assert_eq!(r.matches[0].value, "red");

        // 根节点
        let r = search(&search_req("$", "path")).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.matches[0].value_type, "对象");
    }

    #[test]
    fn path_bracket_name_with_special_chars_round_trips() {
        let req = JsonSearchRequest {
            input: r#"{"a.b":{"c d":1}}"#.to_string(),
            query: r#"$["a.b"]["c d"]"#.to_string(),
            mode: "path".to_string(),
            case_sensitive: false,
            exact: false,
            limit: 200,
        };
        let r = search(&req).unwrap();
        assert_eq!(r.total, 1);
        // 非简单标识符的键在结果路径里用中括号形式回显
        assert_eq!(r.matches[0].path, r#"$["a.b"]["c d"]"#);
    }

    #[test]
    fn path_no_match_is_empty_not_an_error() {
        let r = search(&search_req("$.store.nothing", "path")).unwrap();
        assert_eq!(r.total, 0);
        let r = search(&search_req("$.store.book[99]", "path")).unwrap();
        assert_eq!(r.total, 0);
    }

    #[test]
    fn rejects_bad_path_and_bad_mode() {
        assert!(search(&search_req("$.store[", "path")).is_err());
        assert!(search(&search_req("$.store[abc]", "path")).is_err());
        assert!(search(&search_req("$..", "path")).is_err());
        assert!(search(&search_req("x", "bogus")).is_err());
        assert!(search(&search_req("", "key")).is_err()); // 关键字为空
    }

    #[test]
    fn rejects_invalid_json_everywhere() {
        assert!(format(&fmt_req("{oops}")).is_err());
        assert!(format(&fmt_req("   ")).is_err());
        let mut req = search_req("a", "key");
        req.input = "[1,".to_string();
        assert!(search(&req).is_err());
    }
}
