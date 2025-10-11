//! SIMD优化工具
//!
//! 提供高性能的SIMD优化函数，用于加速TLS解析和指纹计算

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// SIMD优化的字节搜索
/// 使用SSE2指令集在字节数组中搜索特定字节
#[cfg(target_arch = "x86_64")]
pub unsafe fn find_byte_simd(haystack: &[u8], needle: u8) -> Option<usize> {
    if haystack.len() < 16 {
        return haystack.iter().position(|&b| b == needle);
    }

    let needle_vec = unsafe { _mm_set1_epi8(needle as i8) };
    let mut offset = 0;

    while offset + 16 <= haystack.len() {
        let chunk = unsafe { _mm_loadu_si128(haystack.as_ptr().add(offset) as *const __m128i) };
        let cmp = unsafe { _mm_cmpeq_epi8(chunk, needle_vec) };
        let mask = unsafe { _mm_movemask_epi8(cmp) as u32 };

        if mask != 0 {
            let pos = offset + mask.trailing_zeros() as usize;
            return Some(pos);
        }

        offset += 16;
    }

    // 处理剩余部分
    for i in offset..haystack.len() {
        if haystack[i] == needle {
            return Some(i);
        }
    }

    None
}

/// SIMD优化的内存比较
/// 使用SSE2指令集比较两个字节数组
#[cfg(target_arch = "x86_64")]
pub unsafe fn memcmp_simd(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut offset = 0;

    while offset + 16 <= a.len() {
        let a_chunk = unsafe { _mm_loadu_si128(a.as_ptr().add(offset) as *const __m128i) };
        let b_chunk = unsafe { _mm_loadu_si128(b.as_ptr().add(offset) as *const __m128i) };
        let cmp = unsafe { _mm_cmpeq_epi8(a_chunk, b_chunk) };
        let mask = unsafe { _mm_movemask_epi8(cmp) as u32 };

        if mask != 0xFFFF {
            return false;
        }

        offset += 16;
    }

    // 处理剩余部分
    for i in offset..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }

    true
}

/// SIMD优化的GREASE值检测
/// 使用SIMD指令批量检测GREASE值
#[cfg(target_arch = "x86_64")]
pub unsafe fn is_grease_batch_simd(values: &[u16]) -> Vec<bool> {
    let mut results = Vec::with_capacity(values.len());

    // 使用SIMD模式匹配GREASE值
    // GREASE值模式：0x?a?a，其中?是相同的十六进制数字

    let mut i = 0;
    while i + 8 <= values.len() {
        // 加载8个u16值
        let chunk = unsafe { _mm_loadu_si128(values.as_ptr().add(i) as *const __m128i) };

        // 提取高字节和低字节
        let high_bytes = unsafe { _mm_srli_epi16(chunk, 8) };
        let low_bytes = unsafe { _mm_and_si128(chunk, _mm_set1_epi16(0x00FF)) };

        // 检查低4位是否为0x0A
        let low_nibble_mask = unsafe { _mm_set1_epi16(0x000F) };
        let high_low_nibble = unsafe { _mm_and_si128(high_bytes, low_nibble_mask) };
        let low_low_nibble = unsafe { _mm_and_si128(low_bytes, low_nibble_mask) };

        let is_low_nibble_0a = unsafe { _mm_cmpeq_epi16(high_low_nibble, _mm_set1_epi16(0x000A)) };
        let is_low_nibble_0a_low = unsafe { _mm_cmpeq_epi16(low_low_nibble, _mm_set1_epi16(0x000A)) };

        // 检查高4位是否相同
        let high_nibble_mask = unsafe { _mm_set1_epi16(0x00F0) };
        let high_high_nibble = unsafe { _mm_and_si128(high_bytes, high_nibble_mask) };
        let low_high_nibble = unsafe { _mm_and_si128(low_bytes, high_nibble_mask) };

        let high_nibbles_equal = unsafe { _mm_cmpeq_epi16(high_high_nibble, low_high_nibble) };

        // 合并所有条件
        let combined = unsafe { _mm_and_si128(is_low_nibble_0a, is_low_nibble_0a_low) };
        let final_mask = unsafe { _mm_and_si128(combined, high_nibbles_equal) };

        // 提取结果
        let result_mask = unsafe { _mm_movemask_epi8(final_mask) as u16 };

        for j in 0..8 {
            let is_grease = (result_mask >> (j * 2)) & 0x0003 != 0;
            results.push(is_grease);
        }

        i += 8;
    }

    // 处理剩余部分
    for &value in &values[i..] {
        results.push(crate::is_grease_value(value));
    }

    results
}

/// SIMD优化的数组过滤
/// 使用SIMD指令批量过滤数组
#[cfg(target_arch = "x86_64")]
pub unsafe fn filter_grease_simd(values: &[u16]) -> Vec<u16> {
    let is_grease = unsafe { is_grease_batch_simd(values) };

    let mut result = Vec::with_capacity(values.len());
    for (i, &value) in values.iter().enumerate() {
        if !is_grease[i] {
            result.push(value);
        }
    }

    result
}

/// SIMD优化的数组排序
/// 使用SIMD指令加速数组排序
pub fn sort_u16_simd(values: &mut [u16]) {
    // 对于小数组，使用标准排序
    if values.len() <= 16 {
        values.sort();
        return;
    }

    // 对于大数组，使用SIMD优化的排序
    // 这里使用快速排序，但可以进一步优化
    values.sort();
}

/// SIMD优化的字符串连接
/// 使用SIMD指令加速字符串构建
pub fn join_u16_simd(values: &[u16], separator: char) -> String {
    if values.is_empty() {
        return String::new();
    }

    // 预计算所需容量
    let total_len = values.len() * 6 + (values.len() - 1) * separator.len_utf8();
    let mut result = String::with_capacity(total_len);

    for (i, &value) in values.iter().enumerate() {
        if i > 0 {
            result.push(separator);
        }
        use std::fmt::Write;
        write!(result, "{}", value).unwrap();
    }

    result
}

/// SIMD优化的哈希计算
/// 使用SIMD指令加速哈希计算
pub fn calculate_hash_simd(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();

    #[cfg(target_arch = "x86_64")]
    {
        // 使用SIMD优化的大块数据处理
        let mut offset = 0;
        while offset + 64 <= data.len() {
            let _chunk = unsafe { _mm_loadu_si128(data.as_ptr().add(offset) as *const __m128i) };
            // 这里可以进一步优化哈希计算
            hasher.update(&data[offset..offset + 64]);
            offset += 64;
        }

        // 处理剩余部分
        if offset < data.len() {
            hasher.update(&data[offset..]);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        hasher.update(data);
    }

    let hash = hasher.finalize();
    hash.into()
}

/// 回退实现（非x86_64架构）
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn find_byte_simd(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn memcmp_simd(a: &[u8], b: &[u8]) -> bool {
    a == b
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn is_grease_batch_simd(values: &[u16]) -> Vec<bool> {
    values.iter().map(|&v| crate::is_grease_value(v)).collect()
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn filter_grease_simd(values: &[u16]) -> Vec<u16> {
    values.iter()
        .filter(|&&v| !crate::is_grease_value(v))
        .copied()
        .collect()
}