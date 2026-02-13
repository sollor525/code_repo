use std::process::Command;

fn main() -> anyhow::Result<()> {
    // Use aya-build to build the eBPF program
    // This will generate the BPF object file at the expected location
    aya_build::build()?;

    Ok(())
}