use aya::maps::HashMap;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{RawTracePoint,TracePoint, KProbe};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/my-app"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/my-app"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut RawTracePoint = bpf.program_mut("log_syscall").unwrap().try_into()?;
    program.load()?;
    program.attach("sys_enter")?;

    // let program: &mut TracePoint = bpf.program_mut("echo").unwrap().try_into()?;
    // program.load()?;
    // program.attach("syscalls", "sys_enter_openat")?;

    // let kprobe: &mut KProbe = bpf.program_mut("log_pid").unwrap().try_into()?;
    // kprobe.load()?;
    // kprobe.attach("__x64_sys_execve", 0)?;

    // let mut pids = HashMap::try_from(bpf.map_mut("PIDS")?)?;
    // let test=0;
    // output = pids.get(&test).is_some();

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
