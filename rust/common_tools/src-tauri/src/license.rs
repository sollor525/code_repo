//! 软件有效期限制：自**编译之日**起一年。过期后内嵌服务对所有请求返回「已停用」
//! 页面，提示联系邮箱获取新版本。
//!
//! 编译时间由 `build.rs` 通过 `CT_BUILD_EPOCH`（Unix 秒）注入。日期计算为纯函数
//! （`evaluate`），便于测试；运行时用 `status()` 取当前状态。

use chrono::{DateTime, Months, TimeZone, Utc};

/// 获取新版本的联系邮箱
pub const CONTACT_EMAIL: &str = "sollor525@hotmail.com";

/// 有效期长度：编译日起 12 个月
const VALID_MONTHS: u32 = 12;

/// 编译时间（Unix 秒），由 build.rs 注入
fn build_epoch() -> i64 {
    env!("CT_BUILD_EPOCH").parse::<i64>().unwrap_or(0)
}

#[derive(Clone, Copy)]
pub struct LicenseStatus {
    pub build_date: DateTime<Utc>,
    pub expiry_date: DateTime<Utc>,
    pub expired: bool,
    /// 距到期天数；已过期为负。运行时不展示有效期信息（仅测试断言用），故允许未使用。
    #[allow(dead_code)]
    pub days_left: i64,
}

impl LicenseStatus {
    pub fn build_ymd(&self) -> String {
        self.build_date.format("%Y-%m-%d").to_string()
    }
    pub fn expiry_ymd(&self) -> String {
        self.expiry_date.format("%Y-%m-%d").to_string()
    }
}

/// 纯函数：由编译秒与当前时刻得出授权状态（便于单测）
pub fn evaluate(build_epoch: i64, now: DateTime<Utc>) -> LicenseStatus {
    let build_date = Utc
        .timestamp_opt(build_epoch, 0)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).unwrap());
    // 加 12 个月为「一年」（按日历月，闰年自动夹到当月最后一天）
    let expiry_date = build_date
        .checked_add_months(Months::new(VALID_MONTHS))
        .unwrap_or(build_date);
    let expired = now >= expiry_date;
    let days_left = (expiry_date - now).num_days();
    LicenseStatus {
        build_date,
        expiry_date,
        expired,
        days_left,
    }
}

/// 当前授权状态
pub fn status() -> LicenseStatus {
    evaluate(build_epoch(), Utc::now())
}

/// 是否已过期
pub fn is_expired() -> bool {
    status().expired
}

/// 「已停用」页面（自包含内联样式：过期时静态资源同样被拦截，不能外链 CSS）
pub fn expired_html() -> String {
    let s = status();
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>软件已停用 — 开发辅助工具</title>
<style>
  html,body{{height:100%;margin:0}}
  body{{display:flex;align-items:center;justify-content:center;
    background:#0A0D12;color:#C7D0DE;
    font-family:'Chakra Petch','IBM Plex Sans',-apple-system,'Segoe UI',Roboto,'PingFang SC','Microsoft YaHei',sans-serif;}}
  .box{{max-width:520px;width:88%;background:#0F141D;border:1px solid #1E2735;
    border-left:3px solid #E5484D;border-radius:14px;padding:34px 32px;
    box-shadow:0 18px 50px rgba(0,0,0,.45);}}
  .tag{{font-family:ui-monospace,'IBM Plex Mono',monospace;font-size:.72rem;
    letter-spacing:.16em;text-transform:uppercase;color:#E5484D;margin-bottom:14px;}}
  h1{{font-size:1.5rem;margin:0 0 12px;color:#F2F5FA;font-weight:700;}}
  p{{line-height:1.7;margin:0 0 12px;color:#93A0B5;}}
  .meta{{font-family:ui-monospace,'IBM Plex Mono',monospace;font-size:.82rem;
    color:#6B7787;margin-top:18px;padding-top:14px;border-top:1px solid #1E2735;}}
  a{{color:#4FD0E0;text-decoration:none;font-weight:600;}}
  a:hover{{text-decoration:underline;}}
</style></head>
<body><div class="box">
  <div class="tag">● DEACTIVATED · 软件已停用</div>
  <h1>本软件已停止使用</h1>
  <p>本软件自编译之日起有效期一年，现已到期停用。</p>
  <p>如需获取新版本，请联系 <a href="mailto:{email}">{email}</a>。</p>
  <div class="meta">编译日期：{build}　·　有效期至：{expiry}</div>
</div></body></html>"#,
        email = CONTACT_EMAIL,
        build = s.build_ymd(),
        expiry = s.expiry_ymd(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn ts(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
    }

    #[test]
    fn one_year_window_from_build_date() {
        let build = ts(2026, 7, 10);
        let s = evaluate(build.timestamp(), build);
        assert_eq!(s.build_ymd(), "2026-07-10");
        assert_eq!(s.expiry_ymd(), "2027-07-10");
        assert!(!s.expired);
    }

    #[test]
    fn active_just_before_expiry() {
        let build = ts(2026, 7, 10);
        let now = ts(2027, 7, 9); // 到期前一天
        let s = evaluate(build.timestamp(), now);
        assert!(!s.expired);
        assert_eq!(s.days_left, 1);
    }

    #[test]
    fn expired_at_and_after_the_boundary() {
        let build = ts(2026, 7, 10);
        // 恰好到期（>=）即停用
        let at = evaluate(build.timestamp(), ts(2027, 7, 10));
        assert!(at.expired);
        // 过期后 days_left 为负
        let after = evaluate(build.timestamp(), ts(2027, 8, 10));
        assert!(after.expired);
        assert!(after.days_left < 0);
    }

    #[test]
    fn expiry_uses_calendar_months_not_365_days() {
        // 跨闰年 2 月：一年后夹到当月最后一天
        let build = ts(2024, 2, 29);
        let s = evaluate(build.timestamp(), build);
        assert_eq!(s.expiry_ymd(), "2025-02-28");
    }

    #[test]
    fn mid_window_reports_positive_days_left() {
        let build = ts(2026, 7, 10);
        let now = build + Duration::days(100);
        let s = evaluate(build.timestamp(), now);
        assert!(!s.expired);
        assert!(s.days_left > 250 && s.days_left < 270);
    }

    #[test]
    fn expired_page_carries_contact_and_dates() {
        // 直接验证页面文案（用真实 status，仅检查关键字段存在）
        let s = status();
        let _ = s; // status 依赖注入的编译时间，这里不断言其过期与否
        let html = expired_html();
        assert!(html.contains(CONTACT_EMAIL));
        assert!(html.contains("有效期至"));
        assert!(html.contains("软件已停用"));
    }
}
