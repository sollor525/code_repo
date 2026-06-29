//! Crontab 时间计算：解析 5-7 字段的 CRON 表达式，给出中文解释与未来若干次执行
//! 时间；并支持把「每周 / 每天 / 每小时 / 每 N 分钟 / 每 N 秒」等选项转换为 CRON 配置。
//!
//! 纯逻辑，不依赖外部 cron crate：手写字段解析 + 按分钟步进枚举匹配时间（秒级在
//! 匹配分钟内展开），覆盖 `*`、范围 `a-b`、步长 `*/n`、`a-b/n`、列表 `a,b,c`、
//! 月份/星期名称，以及 `@yearly/@monthly/@weekly/@daily/@hourly/@reboot` 宏。
//! 不支持 Quartz 的 `L / W / #` 等高级语法（遇到时报错）。

use chrono::{DateTime, Datelike, Duration, Local, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, PartialEq)]
enum FieldKind {
    Second,
    Minute,
    Hour,
    Dom,
    Month,
    Dow,
    Year,
}

/// 解析后的调度表
struct CronSchedule {
    secs: Vec<u32>,
    mins: Vec<u32>,
    hours: Vec<u32>,
    doms: Vec<u32>,
    months: Vec<u32>,
    dows: Vec<u32>, // 0=周日 .. 6=周六
    years: Option<Vec<i32>>,
    dom_restricted: bool,
    dow_restricted: bool,
    /// 展示顺序的 (字段名, 原始片段, 中文说明)
    fields: Vec<CronField>,
}

// =============================  DTO  =============================

#[derive(Deserialize)]
pub struct CronExplainRequest {
    pub expression: String,
    #[serde(default)]
    pub count: Option<usize>,
}

#[derive(Serialize, Clone)]
pub struct CronField {
    pub label: String,
    pub value: String,
    pub desc: String,
}

#[derive(Serialize)]
pub struct CronExplainResponse {
    pub expression: String,
    pub normalized: String,
    pub field_count: usize,
    pub description: String,
    pub fields: Vec<CronField>,
    pub next_times: Vec<String>,
    pub note: Option<String>,
}

#[derive(Deserialize)]
pub struct CronBuildRequest {
    /// every_n_seconds | every_n_minutes | hourly | daily | weekly | monthly
    pub mode: String,
    #[serde(default)]
    pub n: Option<u32>,
    #[serde(default)]
    pub minute: Option<u32>,
    #[serde(default)]
    pub hour: Option<u32>,
    #[serde(default)]
    pub day_of_week: Option<u32>,
    #[serde(default)]
    pub day_of_month: Option<u32>,
}

#[derive(Serialize)]
pub struct CronBuildResponse {
    pub expression: String,
    pub description: String,
}

// =============================  宏展开  =============================

/// 返回 (展开后的表达式, 是否为 @reboot)
fn expand_macro(expr: &str) -> (String, bool) {
    match expr.trim().to_ascii_lowercase().as_str() {
        "@yearly" | "@annually" => ("0 0 1 1 *".to_string(), false),
        "@monthly" => ("0 0 1 * *".to_string(), false),
        "@weekly" => ("0 0 * * 0".to_string(), false),
        "@daily" | "@midnight" => ("0 0 * * *".to_string(), false),
        "@hourly" => ("0 * * * *".to_string(), false),
        "@reboot" => ("@reboot".to_string(), true),
        _ => (expr.split_whitespace().collect::<Vec<_>>().join(" "), false),
    }
}

// =============================  字段解析  =============================

fn name_to_num(tok: &str, kind: FieldKind) -> Option<u32> {
    let t = tok.to_ascii_lowercase();
    match kind {
        FieldKind::Month => match t.as_str() {
            "jan" => Some(1),
            "feb" => Some(2),
            "mar" => Some(3),
            "apr" => Some(4),
            "may" => Some(5),
            "jun" => Some(6),
            "jul" => Some(7),
            "aug" => Some(8),
            "sep" => Some(9),
            "oct" => Some(10),
            "nov" => Some(11),
            "dec" => Some(12),
            _ => None,
        },
        FieldKind::Dow => match t.as_str() {
            "sun" => Some(0),
            "mon" => Some(1),
            "tue" => Some(2),
            "wed" => Some(3),
            "thu" => Some(4),
            "fri" => Some(5),
            "sat" => Some(6),
            _ => None,
        },
        _ => None,
    }
}

fn resolve(tok: &str, kind: FieldKind, min: u32, max: u32) -> Result<u32, String> {
    let tok = tok.trim();
    let v = if let Some(n) = name_to_num(tok, kind) {
        n
    } else {
        tok.parse::<u32>()
            .map_err(|_| format!("无法识别的取值「{tok}」"))?
    };
    if v < min || v > max {
        return Err(format!("取值「{tok}」超出有效范围 {min}-{max}"));
    }
    Ok(v)
}

fn parse_field(spec: &str, min: u32, max: u32, kind: FieldKind) -> Result<Vec<u32>, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("存在空字段".to_string());
    }
    if spec.contains('L') || spec.contains('l') || spec.contains('W') || spec.contains('w') || spec.contains('#') {
        return Err("暂不支持 L / W / # 等高级语法".to_string());
    }
    if spec == "*" || spec == "?" {
        return Ok((min..=max).collect());
    }
    let mut out: BTreeSet<u32> = BTreeSet::new();
    for term in spec.split(',') {
        let term = term.trim();
        if term.is_empty() {
            return Err("列表中存在空项".to_string());
        }
        // 步长
        let (range_part, step) = match term.split_once('/') {
            Some((r, s)) => {
                let step = s
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| format!("无效的步长「{s}」"))?;
                if step == 0 {
                    return Err("步长不能为 0".to_string());
                }
                (r.trim(), Some(step))
            }
            None => (term, None),
        };
        // 范围
        let (lo, hi) = if range_part == "*" {
            (min, max)
        } else if let Some((a, b)) = range_part.split_once('-') {
            (resolve(a, kind, min, max)?, resolve(b, kind, min, max)?)
        } else {
            let v = resolve(range_part, kind, min, max)?;
            // "a/step" 表示从 a 到上界按步长；单值则就是 a
            if step.is_some() {
                (v, max)
            } else {
                (v, v)
            }
        };
        if lo > hi {
            return Err(format!("范围起点大于终点：{term}"));
        }
        let st = step.unwrap_or(1);
        let mut v = lo;
        while v <= hi {
            out.insert(v);
            v += st;
        }
    }
    if out.is_empty() {
        return Err(format!("字段「{spec}」未匹配到任何取值"));
    }
    Ok(out.into_iter().collect())
}

fn parse_expression(normalized: &str) -> Result<CronSchedule, String> {
    let f: Vec<&str> = normalized.split_whitespace().collect();
    // 按字段数确定语义：5=标准；6=秒+标准；7=秒+标准+年
    let (sec, min, hour, dom, month, dow, year): (
        &str,
        &str,
        &str,
        &str,
        &str,
        &str,
        Option<&str>,
    ) = match f.len() {
        5 => ("0", f[0], f[1], f[2], f[3], f[4], None),
        6 => (f[0], f[1], f[2], f[3], f[4], f[5], None),
        7 => (f[0], f[1], f[2], f[3], f[4], f[5], Some(f[6])),
        n => {
            return Err(format!(
                "CRON 表达式需为 5-7 个字段（当前 {n} 个）。5=分时日月周，6=加秒，7=加年"
            ))
        }
    };

    let secs = parse_field(sec, 0, 59, FieldKind::Second)?;
    let mins = parse_field(min, 0, 59, FieldKind::Minute)?;
    let hours = parse_field(hour, 0, 23, FieldKind::Hour)?;
    let doms = parse_field(dom, 1, 31, FieldKind::Dom)?;
    let months = parse_field(month, 1, 12, FieldKind::Month)?;
    // 星期允许 7（=周日），解析后归一到 0-6
    let dows_raw = parse_field(dow, 0, 7, FieldKind::Dow)?;
    let dows: Vec<u32> = {
        let mut s: BTreeSet<u32> = BTreeSet::new();
        for d in dows_raw {
            s.insert(if d == 7 { 0 } else { d });
        }
        s.into_iter().collect()
    };
    let years = match year {
        Some(y) => Some(
            parse_field(y, 1970, 2099, FieldKind::Year)?
                .into_iter()
                .map(|v| v as i32)
                .collect(),
        ),
        None => None,
    };

    let is_any = |s: &str| s == "*" || s == "?";
    let dom_restricted = !is_any(dom);
    let dow_restricted = !is_any(dow);

    // 展示字段（含中文说明）
    let mut fields = Vec::new();
    if f.len() >= 6 {
        fields.push(CronField {
            label: "秒".into(),
            value: sec.into(),
            desc: describe_field(sec, FieldKind::Second),
        });
    }
    fields.push(CronField {
        label: "分".into(),
        value: min.into(),
        desc: describe_field(min, FieldKind::Minute),
    });
    fields.push(CronField {
        label: "时".into(),
        value: hour.into(),
        desc: describe_field(hour, FieldKind::Hour),
    });
    fields.push(CronField {
        label: "日".into(),
        value: dom.into(),
        desc: describe_field(dom, FieldKind::Dom),
    });
    fields.push(CronField {
        label: "月".into(),
        value: month.into(),
        desc: describe_field(month, FieldKind::Month),
    });
    fields.push(CronField {
        label: "周".into(),
        value: dow.into(),
        desc: describe_field(dow, FieldKind::Dow),
    });
    if let Some(y) = year {
        fields.push(CronField {
            label: "年".into(),
            value: y.into(),
            desc: describe_field(y, FieldKind::Year),
        });
    }

    Ok(CronSchedule {
        secs,
        mins,
        hours,
        doms,
        months,
        dows,
        years,
        dom_restricted,
        dow_restricted,
        fields,
    })
}

// =============================  中文描述  =============================

fn unit_word(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Second => "秒",
        FieldKind::Minute => "分",
        FieldKind::Hour => "时",
        FieldKind::Dom => "日",
        FieldKind::Month => "月",
        FieldKind::Dow => "周",
        FieldKind::Year => "年",
    }
}

fn every_word(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Second => "每秒",
        FieldKind::Minute => "每分钟",
        FieldKind::Hour => "每小时",
        FieldKind::Dom => "每天",
        FieldKind::Month => "每月",
        FieldKind::Dow => "不限星期几",
        FieldKind::Year => "每年",
    }
}

fn zh_dow(n: u32) -> String {
    let names = ["日", "一", "二", "三", "四", "五", "六"];
    let idx = (if n == 7 { 0 } else { n }) as usize;
    format!("周{}", names.get(idx).copied().unwrap_or("?"))
}

/// 单个取值的展示（星期/月份用更友好的名称）
fn value_label(v: &str, kind: FieldKind) -> String {
    let num = name_to_num(v, kind).map(|n| n.to_string());
    match kind {
        FieldKind::Dow => {
            let n = num
                .as_deref()
                .or(Some(v))
                .and_then(|s| s.parse::<u32>().ok());
            match n {
                Some(n) => zh_dow(n),
                None => v.to_string(),
            }
        }
        FieldKind::Month => {
            let n = num.as_deref().or(Some(v)).and_then(|s| s.parse::<u32>().ok());
            match n {
                Some(n) => format!("{n} 月"),
                None => v.to_string(),
            }
        }
        _ => format!("{v} {}", unit_word(kind)),
    }
}

fn describe_term(term: &str, kind: FieldKind) -> String {
    let (range_part, step) = match term.split_once('/') {
        Some((r, s)) => (r.trim(), Some(s.trim())),
        None => (term, None),
    };
    let unit = unit_word(kind);
    if range_part == "*" {
        return match step {
            Some(s) => format!("每 {s} {unit}"),
            None => every_word(kind).to_string(),
        };
    }
    if let Some((a, b)) = range_part.split_once('-') {
        let base = format!("{} 到 {}", value_label(a, kind), value_label(b, kind));
        return match step {
            Some(s) => format!("{base} 间每 {s} {unit}"),
            None => base,
        };
    }
    match step {
        Some(s) => format!("自 {} 起每 {s} {unit}", value_label(range_part, kind)),
        None => value_label(range_part, kind),
    }
}

fn describe_field(spec: &str, kind: FieldKind) -> String {
    let spec = spec.trim();
    if spec == "*" || spec == "?" {
        return every_word(kind).to_string();
    }
    spec.split(',')
        .map(|t| describe_term(t.trim(), kind))
        .collect::<Vec<_>>()
        .join("、")
}

impl CronSchedule {
    /// 一句话描述
    fn description(&self) -> String {
        let mut clauses: Vec<String> = Vec::new();
        for fld in &self.fields {
            if fld.value == "*" || fld.value == "?" {
                continue;
            }
            clauses.push(format!("{}：{}", fld.label, fld.desc));
        }
        if clauses.is_empty() {
            // 全 * —— 按最小粒度
            let has_sec = self.fields.iter().any(|f| f.label == "秒");
            return if has_sec {
                "每秒执行".to_string()
            } else {
                "每分钟执行".to_string()
            };
        }
        if self.dom_restricted && self.dow_restricted {
            clauses.push("（日、周均限定时，满足任一即触发）".to_string());
        }
        format!("{} 执行", clauses.join("，"))
    }

    fn minute_matches(&self, t: &DateTime<Local>) -> bool {
        if !self.mins.contains(&t.minute()) {
            return false;
        }
        if !self.hours.contains(&t.hour()) {
            return false;
        }
        if !self.months.contains(&t.month()) {
            return false;
        }
        if let Some(years) = &self.years {
            if !years.contains(&t.year()) {
                return false;
            }
        }
        let dom_ok = self.doms.contains(&t.day());
        let dow_ok = self.dows.contains(&t.weekday().num_days_from_sunday());
        if self.dom_restricted && self.dow_restricted {
            dom_ok || dow_ok
        } else {
            dom_ok && dow_ok
        }
    }

    /// 计算 `now` 之后的若干次执行时间（按分钟步进，秒在匹配分钟内展开）
    fn next_times(&self, now: DateTime<Local>, count: usize) -> (Vec<DateTime<Local>>, Option<String>) {
        let mut results: Vec<DateTime<Local>> = Vec::new();
        // 截断到当前分钟边界
        let mut t = now
            .with_second(0)
            .and_then(|x| x.with_nanosecond(0))
            .unwrap_or(now);
        let mut iter: u64 = 0;
        const MAX_ITER: u64 = 6_000_000; // ~11 年的分钟数，足够覆盖每年一次的场景

        while results.len() < count && iter < MAX_ITER {
            if self.minute_matches(&t) {
                for &s in &self.secs {
                    if let Some(cand) = t.with_second(s) {
                        if cand > now {
                            results.push(cand);
                            if results.len() >= count {
                                break;
                            }
                        }
                    }
                }
            }
            t = t + Duration::minutes(1);
            iter += 1;
        }

        let note = if results.len() < count {
            Some(format!(
                "在约 11 年内仅找到 {} 次执行时间（可能是较稀疏的表达式）",
                results.len()
            ))
        } else {
            None
        };
        (results, note)
    }
}

// =============================  对外接口  =============================

pub fn explain(expr: &str, count: usize) -> Result<CronExplainResponse, String> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err("请输入 CRON 表达式".to_string());
    }
    let (normalized, is_reboot) = expand_macro(trimmed);
    if is_reboot {
        return Ok(CronExplainResponse {
            expression: trimmed.to_string(),
            normalized: "@reboot".to_string(),
            field_count: 0,
            description: "系统启动时执行一次".to_string(),
            fields: vec![],
            next_times: vec![],
            note: Some("@reboot 在系统启动时触发，无法计算具体时间".to_string()),
        });
    }

    let sched = parse_expression(&normalized)?;
    let field_count = normalized.split_whitespace().count();
    let count = count.clamp(1, 50);
    let (times, note) = sched.next_times(Local::now(), count);
    let next_times = times
        .iter()
        .map(|t| format!("{} {}", t.format("%Y-%m-%d %H:%M:%S"), zh_dow(t.weekday().num_days_from_sunday())))
        .collect();

    Ok(CronExplainResponse {
        expression: trimmed.to_string(),
        normalized,
        field_count,
        description: sched.description(),
        fields: sched.fields.clone(),
        next_times,
        note,
    })
}

pub fn build(req: &CronBuildRequest) -> Result<CronBuildResponse, String> {
    let minute = req.minute.unwrap_or(0);
    let hour = req.hour.unwrap_or(0);
    if minute > 59 {
        return Err("分钟需在 0-59 之间".to_string());
    }
    if hour > 23 {
        return Err("小时需在 0-23 之间".to_string());
    }

    let (expression, description) = match req.mode.as_str() {
        "every_n_seconds" => {
            let n = req.n.unwrap_or(0);
            if !(1..=59).contains(&n) {
                return Err("秒间隔需在 1-59 之间".to_string());
            }
            (format!("*/{n} * * * * *"), format!("每 {n} 秒执行一次"))
        }
        "every_n_minutes" => {
            let n = req.n.unwrap_or(0);
            if !(1..=59).contains(&n) {
                return Err("分钟间隔需在 1-59 之间".to_string());
            }
            (format!("*/{n} * * * *"), format!("每 {n} 分钟执行一次"))
        }
        "hourly" => (
            format!("{minute} * * * *"),
            format!("每小时的第 {minute} 分钟执行"),
        ),
        "daily" => (
            format!("{minute} {hour} * * *"),
            format!("每天 {hour:02}:{minute:02} 执行"),
        ),
        "weekly" => {
            let dow = req.day_of_week.unwrap_or(1);
            if dow > 6 {
                return Err("星期需在 0-6 之间（0=周日）".to_string());
            }
            (
                format!("{minute} {hour} * * {dow}"),
                format!("每{} {hour:02}:{minute:02} 执行", zh_dow(dow)),
            )
        }
        "monthly" => {
            let dom = req.day_of_month.unwrap_or(1);
            if !(1..=31).contains(&dom) {
                return Err("日期需在 1-31 之间".to_string());
            }
            (
                format!("{minute} {hour} {dom} * *"),
                format!("每月 {dom} 日 {hour:02}:{minute:02} 执行"),
            )
        }
        other => return Err(format!("未知的生成模式：{other}")),
    };

    Ok(CronBuildResponse {
        expression,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_five_fields_and_counts() {
        let r = explain("*/15 9-17 * * 1-5", 7).unwrap();
        assert_eq!(r.field_count, 5);
        assert_eq!(r.next_times.len(), 7);
        assert!(r.fields.iter().any(|f| f.label == "分"));
    }

    #[test]
    fn supports_seconds_and_year_fields() {
        assert_eq!(explain("0 0 12 * * *", 3).unwrap().field_count, 6);
        let r = explain("0 0 0 1 1 * 2030", 1).unwrap();
        assert_eq!(r.field_count, 7);
        assert!(r.next_times[0].starts_with("2030-01-01 00:00:00"));
    }

    #[test]
    fn expands_macros_and_reboot() {
        assert_eq!(explain("@daily", 1).unwrap().normalized, "0 0 * * *");
        let rb = explain("@reboot", 7).unwrap();
        assert!(rb.next_times.is_empty());
        assert!(rb.note.is_some());
    }

    #[test]
    fn names_and_steps() {
        // 周一到周五、每月、JAN-DEC
        let r = explain("0 8 * JAN-MAR MON-FRI", 5).unwrap();
        assert_eq!(r.next_times.len(), 5);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(explain("* * *", 7).is_err()); // 字段过少
        assert!(explain("99 * * * *", 7).is_err()); // 越界
        assert!(explain("0 0 L * *", 7).is_err()); // 不支持 L
    }

    #[test]
    fn build_modes() {
        let req = CronBuildRequest {
            mode: "every_n_minutes".into(),
            n: Some(5),
            minute: None,
            hour: None,
            day_of_week: None,
            day_of_month: None,
        };
        assert_eq!(build(&req).unwrap().expression, "*/5 * * * *");

        let req = CronBuildRequest {
            mode: "weekly".into(),
            n: None,
            minute: Some(30),
            hour: Some(9),
            day_of_week: Some(1),
            day_of_month: None,
        };
        assert_eq!(build(&req).unwrap().expression, "30 9 * * 1");
    }
}
