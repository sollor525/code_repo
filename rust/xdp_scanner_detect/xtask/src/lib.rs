use aya_build::{build_ebpf, Package, Toolchain};

pub fn xtask_build_ebpf() -> anyhow::Result<()> {
    // 使用 Package 结构体配置 eBPF 程序构建
    build_ebpf(
        [Package {
            name: "xdp-scanner-detect-ebpf",
            root_dir: "../ebpf",
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Nightly
    )
}
