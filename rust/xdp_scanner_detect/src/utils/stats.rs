//! 统计工具

/// 统计工具函数
pub struct StatsUtils;

impl StatsUtils {
    /// 计算移动平均值
    pub fn moving_average(current_avg: f64, new_value: f64, alpha: f64) -> f64 {
        alpha * new_value + (1.0 - alpha) * current_avg
    }

    /// 计算百分位数
    pub fn percentile(_values: &[f64], _percentile: f64) -> f64 {
        // TODO: 实现百分位数计算
        0.0
    }
}