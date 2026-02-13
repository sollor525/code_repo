//! XDP Maps 访问接口

use aya::{Ebpf, maps::{PerCpuArray, Map, MapData}};
use anyhow::{Result, anyhow};

/// XDP Maps 访问接口
pub struct XdpMaps<'a> {
    ebpf: &'a Ebpf,
}

impl<'a> XdpMaps<'a> {
    /// 创建新的 Maps 访问接口
    pub fn new(ebpf: &'a Ebpf) -> Self {
        Self { ebpf }
    }

    /// 从 PerCpuArray 读取并聚合所有 CPU 的值
    fn read_percpu_array_sum(&self, map_name: &str, index: u32) -> Result<u64> {
        let map: &Map = self.ebpf.map(map_name)
            .ok_or_else(|| anyhow!("找不到 map {}", map_name))?;

        // PerCpuArray<T, V>: T=&MapData, V=u64
        let array: PerCpuArray<&MapData, u64> = PerCpuArray::try_from(map)
            .map_err(|_| anyhow!("map {} 不是 PerCpuArray<u64> 类型", map_name))?;

        let values = array.get(&index, 0)
            .map_err(|e| anyhow!("读取 map {} 失败: {}", map_name, e))?;

        // 聚合所有 CPU 的值
        let mut sum: u64 = 0;
        for value in values.iter() {
            sum += *value;
        }
        Ok(sum)
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> Result<crate::xdp::XdpProgramStats> {
        // 统计计数器索引（必须与 eBPF 代码中定义一致）
        const STATS_TOTAL_PACKETS: u32 = 0;
        const STATS_TCP_PACKETS: u32 = 1;
        const STATS_NEW_SESSIONS: u32 = 2;
        const STATS_MALFORMED_PACKETS: u32 = 4;
        const STATS_SCANNER_DETECTED: u32 = 6;
        const STATS_MALICIOUS_SESSIONS: u32 = 7;

        // 直接读取，不使用 unwrap_or，以便看到错误
        let total_packets = self.read_percpu_array_sum("STATS", STATS_TOTAL_PACKETS)?;
        let tcp_packets = self.read_percpu_array_sum("STATS", STATS_TCP_PACKETS)?;
        let new_sessions = self.read_percpu_array_sum("STATS", STATS_NEW_SESSIONS)?;
        let malformed_packets = self.read_percpu_array_sum("STATS", STATS_MALFORMED_PACKETS)?;
        let scanner_detected = self.read_percpu_array_sum("STATS", STATS_SCANNER_DETECTED)?;
        let malicious_sessions = self.read_percpu_array_sum("STATS", STATS_MALICIOUS_SESSIONS)?;

        Ok(crate::xdp::XdpProgramStats {
            total_packets,
            tcp_packets,
            new_sessions,
            malformed_packets,
            scanner_detected,
            malicious_sessions,
            dropped_packets: scanner_detected + malicious_sessions,
            ..Default::default()
        })
    }

    /// 获取 TCP 会话数量
    pub fn get_tcp_session_count(&self) -> Result<usize> {
        use aya::maps::HashMap;

        let _sessions: HashMap<&MapData, u32, u32> = HashMap::try_from(
            self.ebpf.map("TCP_SESSIONS")
                .ok_or_else(|| anyhow!("找不到 TCP_SESSIONS map"))?
        ).map_err(|_| anyhow!("TCP_SESSIONS 不是 HashMap 类型"))?;

        // 注意：aya 的 HashMap 没有直接获取元素数量的方法
        // 这里返回 0，实际实现需要遍历或使用其他方法
        Ok(0)
    }
}
