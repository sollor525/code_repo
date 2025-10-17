//! 指纹匹配测试程序
//!
//! 测试JA4指纹数据库预加载和匹配功能

use std::ffi::CString;
use tls_ja4::c_api::*;

fn main() {
    println!("🔍 测试JA4指纹数据库匹配功能");

    // 初始化上下文
    let ctx = tls_init();
    if ctx.is_null() {
        println!("❌ 初始化失败");
        return;
    }

    // 加载JA4数据库
    let db_path = CString::new("config/ja4_db.json").unwrap();
    let result = tls_load_database(ctx, db_path.as_ptr());

    if result == TLS_JA4_SUCCESS {
        println!("✅ JA4数据库加载成功");
    } else {
        println!("❌ JA4数据库加载失败，错误码: {}", result);
        tls_cleanup(ctx);
        return;
    }

    // 测试一些已知的JA4指纹
    let test_fingerprints = vec![
        "t13d1517h2_8daaf6152771_b0da82dd1658",
        "t13i181000_85036bcba153_d41ae481755e",
        "t13d1516h2_8daaf6152771_02713d6af862",
        "q13d0312h3_55b375c5d22e_06cda9e17597",
        "t13d1517h2_8daaf6152771_b1ff8ab2d16f",
        "t13d190900_9dc949149365_97f8aa674fd9",
        "unknown_fingerprint_for_testing",
    ];

    println!("\n🧪 测试指纹匹配:");
    for (i, fingerprint) in test_fingerprints.iter().enumerate() {
        let fp_cstr = CString::new(*fingerprint).unwrap();
        let match_result = tls_match_fingerprint(ctx, fp_cstr.as_ptr());

        match match_result {
            1 => println!("  {}. {} ✅ 匹配", i + 1, fingerprint),
            0 => println!("  {}. {} ❌ 不匹配", i + 1, fingerprint),
            _ => println!("  {}. {} ⚠️  错误", i + 1, fingerprint),
        }
    }

    println!("\n📊 测试完成");

    // 清理资源
    tls_cleanup(ctx);
}