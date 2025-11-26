use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use web_scan_rust::{WebScanEngine, ProtocolDetector};
use std::io::Write;

fn bench_protocol_detection(c: &mut Criterion) {
    let detector = ProtocolDetector::new();
    
    let test_payloads = vec![
        ("http_get", b"GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice()),
        ("http_post", b"POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"test\":\"data\"}".as_slice()),
        ("https_handshake", &[0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c]),
        ("http2_preface", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()),
        ("unknown_data", b"UNKNOWN_PROTOCOL_DATA_HERE".as_slice()),
    ];

    let mut group = c.benchmark_group("protocol_detection");
    
    for (name, payload) in test_payloads {
        group.bench_with_input(
            BenchmarkId::new("detect", name),
            payload,
            |b, payload| {
                b.iter(|| detector.detect(black_box(payload)))
            },
        );
    }
    
    group.finish();
}

fn bench_rule_matching(c: &mut Criterion) {
    let mut engine = WebScanEngine::new();
    
    // Create a temporary rules file for testing with .rules extension
    let rules_content = r#"
alert http any any -> any any (msg:"Admin access"; content:"/admin/"; sid:1001;)
alert http any any -> any any (msg:"Login page"; content:"login.php"; sid:1002;)
alert http any any -> any any (msg:"SQL injection"; content:"union select"; sid:1003;)
alert http any any -> any any (msg:"XSS attempt"; content:"<script>"; sid:1004;)
alert http any any -> any any (msg:"Directory traversal"; content:"../"; sid:1005;)
"#;
    
    // Create a temporary file with .rules extension
    let mut temp_file = tempfile::Builder::new()
        .suffix(".rules")
        .tempfile()
        .unwrap();
    temp_file.write_all(rules_content.as_bytes()).unwrap();
    
    engine.init_with_rules(temp_file.path().to_str().unwrap()).unwrap();
    
    let large_payload = vec![b'A'; 4096];
    let test_payloads = vec![
        ("admin_access", b"GET /admin/login.php HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice()),
        ("sql_injection", b"GET /search?q=1' union select * from users-- HTTP/1.1\r\n\r\n".as_slice()),
        ("xss_attempt", b"GET /comment?text=<script>alert('xss')</script> HTTP/1.1\r\n\r\n".as_slice()),
        ("normal_request", b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".as_slice()),
        ("large_payload", large_payload.as_slice()),
    ];

    let mut group = c.benchmark_group("rule_matching");
    
    for (name, payload) in test_payloads {
        group.bench_with_input(
            BenchmarkId::new("process", name),
            payload,
            |b, payload| {
                b.iter(|| engine.process_payload(black_box(payload)))
            },
        );
    }
    
    group.finish();
}

fn bench_concurrent_processing(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;
    
    let engine = Arc::new({
        let mut engine = WebScanEngine::new();
        let rules_content = r#"
alert http any any -> any any (msg:"Test rule"; content:"test"; sid:1001;)
"#;
        // Create a temporary file with .rules extension
        let mut temp_file = tempfile::Builder::new()
            .suffix(".rules")
            .tempfile()
            .unwrap();
        temp_file.write_all(rules_content.as_bytes()).unwrap();
        engine.init_with_rules(temp_file.path().to_str().unwrap()).unwrap();
        engine
    });
    
    let payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
    
    c.bench_function("concurrent_processing", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4).map(|_| {
                let engine = Arc::clone(&engine);
                let payload = payload.clone();
                thread::spawn(move || {
                    for _ in 0..100 {
                        let _ = engine.process_payload(black_box(payload.as_slice()));
                    }
                })
            }).collect();
            
            for handle in handles {
                handle.join().unwrap();
            }
        })
    });
}

criterion_group!(
    benches,
    bench_protocol_detection,
    bench_rule_matching,
    bench_concurrent_processing
);
criterion_main!(benches);