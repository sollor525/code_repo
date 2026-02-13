//! 辅助函数模块
//!
//! 提供 eBPF 程序的通用辅助函数，包括：
//! - 时间和计数器函数
//! - 内存操作函数
//! - 性能优化函数

use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_get_smp_processor_id};

/// 网络字节序转换辅助函数
#[inline(always)]
pub fn be_to_h32(be: u32) -> u32 {
    u32::from_be(be)
}

#[inline(always)]
pub fn be_to_h16(be: u16) -> u16 {
    u16::from_be(be)
}

#[inline(always)]
pub fn h_to_be32(h: u32) -> u32 {
    h.to_be()
}

#[inline(always)]
pub fn h_to_be16(h: u16) -> u16 {
    h.to_be()
}

/// 快速字符串比较（用于协议匹配）
#[inline(always)]
pub fn fast_str_cmp(s1: &[u8], s2: &[u8], len: usize) -> bool {
    if len > s1.len() || len > s2.len() {
        return false;
    }

    for i in 0..len {
        if s1[i] != s2[i] {
            return false;
        }
    }

    true
}

/// 计算简单的哈希值
#[inline(always)]
pub fn simple_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;

    for &byte in data {
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(byte as u32);
    }

    hash
}

/// 计算 IP 地址哈希
#[inline(always)]
pub fn ip_hash(ip: u32) -> u32 {
    // 使用 FNV-1a hash 的变体
    let mut hash = 2166136261u32;
    let mut x = ip;

    for _ in 0..4 {
        hash ^= x & 0xFF;
        hash = hash.wrapping_mul(16777619);
        x >>= 8;
    }

    hash
}

/// 检查 IP 是否在指定网段内
#[inline(always)]
pub fn ip_in_network(ip: u32, network: u32, mask: u32) -> bool {
    (ip & mask) == (network & mask)
}

/// 比较两个 IP 地址的差异（用于 TTL 分析）
#[inline(always)]
pub fn ip_distance(ip1: u32, ip2: u32) -> u32 {
    let mut distance = 0;
    let mut diff = ip1 ^ ip2;

    while diff != 0 {
        distance += diff & 1;
        diff >>= 1;
    }

    distance
}

/// 计算 TCP 序列号距离
#[inline(always)]
pub fn seq_distance(seq1: u32, seq2: u32) -> u32 {
    // 处理序列号回环
    if seq2 >= seq1 {
        seq2 - seq1
    } else {
        0xFFFFFFFF - seq1 + seq2 + 1
    }
}

/// 检查序列号是否在有效窗口内
#[inline(always)]
pub fn is_valid_sequence(expected: u32, received: u32, window: u32) -> bool {
    let distance = seq_distance(expected, received);
    distance <= window
}

/// 快速 min 函数（避免分支）
#[inline(always)]
pub fn fast_min(a: u32, b: u32) -> u32 {
    let diff = a.wrapping_sub(b);
    b + (diff & (!diff >> 31))
}

/// 快速 max 函数（避免分支）
#[inline(always)]
pub fn fast_max(a: u32, b: u32) -> u32 {
    let diff = a.wrapping_sub(b);
    a - (diff & (!diff >> 31))
}

/// 检查是否为 2 的幂
#[inline(always)]
pub fn is_power_of_two(x: u32) -> bool {
    x != 0 && (x & (x - 1)) == 0
}

/// 向上对齐到 2 的幂
#[inline(always)]
pub fn align_up_pow2(x: u32, align: u32) -> u32 {
    debug_assert!(is_power_of_two(align));
    (x + align - 1) & !(align - 1)
}

/// 获取当前 CPU ID
#[inline(always)]
pub fn get_cpu_id() -> u32 {
    unsafe { bpf_get_smp_processor_id() }
}

/// 获取纳秒级时间戳
#[inline(always)]
pub fn get_timestamp_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

/// 将纳秒转换为秒
#[inline(always)]
pub fn ns_to_sec(ns: u64) -> u64 {
    ns / 1_000_000_000
}

/// 将纳秒转换为毫秒
#[inline(always)]
pub fn ns_to_ms(ns: u64) -> u64 {
    ns / 1_000_000
}

/// 计算时间差（毫秒）
#[inline(always)]
pub fn time_diff_ms(start: u64, end: u64) -> u64 {
    ns_to_ms(end.saturating_sub(start))
}

/// 性能计数器结构
#[repr(C)]
pub struct PerfCounter {
    pub count: u64,
    pub total_time: u64,
    pub min_time: u64,
    pub max_time: u64,
}

impl PerfCounter {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            count: 0,
            total_time: 0,
            min_time: u64::MAX,
            max_time: 0,
        }
    }

    #[inline(always)]
    pub fn update(&mut self, duration: u64) {
        self.count += 1;
        self.total_time += duration;

        if duration < self.min_time {
            self.min_time = duration;
        }

        if duration > self.max_time {
            self.max_time = duration;
        }
    }

    #[inline(always)]
    pub fn average(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.total_time / self.count
        }
    }
}

/// 指数移动平均滤波器
#[repr(C)]
pub struct ExponentialMovingAverage {
    pub alpha: u32,  // 平滑因子 (0-100)
    pub value: u64,  // 当前值
}

impl ExponentialMovingAverage {
    #[inline(always)]
    pub fn new(alpha: u32, initial_value: u64) -> Self {
        Self {
            alpha,
            value: initial_value,
        }
    }

    #[inline(always)]
    pub fn update(&mut self, new_value: u64) {
        // EMA = alpha * new + (1 - alpha) * old
        self.value = ((self.alpha as u64 * new_value) +
                      ((100 - self.alpha) as u64 * self.value)) / 100;
    }

    #[inline(always)]
    pub fn get(&self) -> u64 {
        self.value
    }
}

/// 简单的随机数生成器（XOR shift）
#[derive(Copy, Clone)]
pub struct SimpleRng {
    state: u32,
}

impl SimpleRng {
    #[inline(always)]
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    #[inline(always)]
    pub fn next(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 17;
        self.state ^= self.state << 5;
        self.state
    }

    #[inline(always)]
    pub fn next_range(&mut self, min: u32, max: u32) -> u32 {
        if min >= max {
            return min;
        }
        min + (self.next() % (max - min))
    }
}

/// 内存对齐检查
#[inline(always)]
pub fn is_aligned(ptr: *const u8, alignment: usize) -> bool {
    (ptr as usize) & (alignment - 1) == 0
}

/// 安全的内存拷贝（在 eBPF 限制内）
#[inline(always)]
pub fn safe_memcpy(dst: *mut u8, src: *const u8, len: usize) -> bool {
    if len > 64 {  // eBPF 栈大小限制
        return false;
    }

    unsafe {
        for i in 0..len {
            *dst.add(i) = *src.add(i);
        }
    }

    true
}

/// 比较两个内存区域
#[inline(always)]
pub fn safe_memcmp(a: *const u8, b: *const u8, len: usize) -> bool {
    if len > 64 {
        return false;
    }

    unsafe {
        for i in 0..len {
            if *a.add(i) != *b.add(i) {
                return false;
            }
        }
    }

    true
}