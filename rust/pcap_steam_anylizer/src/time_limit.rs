//! 使用时间限制检查模块
//!
//! 此模块用于检查程序的使用时间是否在有效期内

use chrono::{Utc, NaiveDate};
use std::process;

/// 软件到期日期（2026年6月30日）
const EXPIRY_DATE: &str = "2026-06-30";

/// 检查程序是否在有效期内
pub fn check_expiry() {
    // 解析到期日期
    let expiry_date = match NaiveDate::parse_from_str(EXPIRY_DATE, "%Y-%m-%d") {
        Ok(date) => date,
        Err(e) => {
            eprintln!("内部错误：无法解析到期日期 - {}", e);
            process::exit(1);
        }
    };

    // 获取当前UTC时间
    let now = Utc::now().date_naive();

    // 检查是否已过期
    if now > expiry_date {
        eprintln!("============================================");
        eprintln!("              软件使用期限已到期");
        eprintln!("============================================");
        eprintln!("本软件的试用/使用期已于 {} 到期", EXPIRY_DATE);
        eprintln!("");
        eprintln!("如需继续使用，请联系管理员获取更新版本。");
        eprintln!("============================================");
        process::exit(1);
    }

    // 计算剩余天数（仅在剩余天数少于30天时显示）
    let days_remaining = (expiry_date - now).num_days();
    if days_remaining > 0 && days_remaining <= 30 {
        eprintln!("提示：软件将在 {} 天后到期（{}）", days_remaining, EXPIRY_DATE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Datelike};

    #[test]
    fn test_expiry_date_parsing() {
        let expiry_date = NaiveDate::parse_from_str(EXPIRY_DATE, "%Y-%m-%d").unwrap();
        assert_eq!(expiry_date.year(), 2026);
        assert_eq!(expiry_date.month(), 6);
        assert_eq!(expiry_date.day(), 30);
    }

    #[test]
    fn test_future_date() {
        let future = NaiveDate::from_ymd_opt(2026, 6, 29).unwrap();
        let expiry = NaiveDate::parse_from_str(EXPIRY_DATE, "%Y-%m-%d").unwrap();
        assert!(future <= expiry);
    }
}