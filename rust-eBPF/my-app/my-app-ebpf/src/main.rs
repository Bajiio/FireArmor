#![no_std]
#![no_main]

#[allow(unused)]
use aya_bpf::{
    helpers::*,
    cty::c_long,
    macros::{tracepoint, kprobe, map, raw_tracepoint},
    maps::{HashMap, PerfEventArray,PerCpuArray},
    programs::{ProbeContext, RawTracePointContext, TracePointContext},
    BpfContext, PtRegs,
    
};
use core::slice;


const LOG_BUF_CAPACITY: usize = 1024;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[allow(unused)]
use aya_log_ebpf::{info,error};

use syscall_digest_common::{Filename, SyscallLog};

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SyscallLog> =
    PerfEventArray::<SyscallLog>::with_max_entries(1024, 0);

#[map(name = "PIDS")]
static mut PIDS: HashMap<u32, Filename> = HashMap::with_max_entries(1024, 0);

#[map(name = "FILENAME")]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);


#[raw_tracepoint]
pub fn log_syscall(ctx: RawTracePointContext) -> u32 {
    match unsafe { try_log_syscall(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}




unsafe fn try_log_syscall(ctx: RawTracePointContext) -> Result<u32, u32> {
    let args = slice::from_raw_parts(ctx.as_ptr() as *const usize, 2);
    let syscall = args[1] as u64;
    let pid = ctx.pid();
    let log_entry = SyscallLog {
        pid,
        syscall: syscall as u32,
    };
    EVENTS.output(&ctx, &log_entry, 0);
    info!(&ctx,"pid: {}", pid);
    info!(&ctx,"syscall: {} \n", syscall);
    Ok(0)
}



// #[tracepoint(name = "echo")]
// pub fn echo_trace_open(ctx: TracePointContext) -> c_long {
//     match try_echo_trace_open(ctx) {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// fn try_echo_trace_open(ctx: TracePointContext) -> Result<c_long, c_long> {
//     // Load the pointer to the filename. The offset value can be found running:
//     // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
//     const FILENAME_OFFSET: usize = 24;
//     let filename_addr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET)? };

//     // get the map-backed buffer that we're going to use as storage for the filename
//     let buf = unsafe {
//         let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
//         &mut *ptr
//     };

//     // read the filename
//     let filename = unsafe {
//         core::str::from_utf8_unchecked(bpf_probe_read_user_str_bytes(
//             filename_addr as *const u8,
//             &mut buf.buf,
//         )?)
//     };
//     let mut u=0;
//     // log the filename
//     info!(&ctx, "filename: {}", filename);

//     Ok(0)
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// #[kprobe]
// pub fn log_pid(ctx: ProbeContext) -> u32 {
//     match unsafe { try_log_pid(ctx) } {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// unsafe fn try_log_pid(ctx: ProbeContext) -> Result<u32, u32> {
//     let pid = ctx.pid();

//     if PIDS.get(&pid).is_none() {
//         let regs = PtRegs::new(ctx.arg(0).unwrap());
//         let filename_addr: *const u8 = regs.arg(0).unwrap();

//         let mut buf = [0u8; 127];
//         let filename_len = bpf_probe_read_user_str_bytes(filename_addr as *const u8, &mut buf)
//             .map_err(|e| e as u32)?.len();

//         let log_entry = Filename {
//             filename: buf,
//             filename_len:filename_len.len(),
//         };
//         info!(&ctx,"filename: {}", log_entry.filename_len);
//     }

//     Ok(0)
// }

// --------------------------------------------------------------------------------

// #[tracepoint(name="my_app")]
// pub fn my_app(ctx: TracePointContext) -> u32 {
//     match try_my_app(ctx) {
//         Ok(ret) => ret,
//         Err(ret) => ret,
//     }
// }

// fn try_my_app(ctx: TracePointContext) -> Result<u32, u32> {
//     info!(&ctx, "tracepoint sys_enter_openat called ");
//     Ok(0)
// }

// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
//     unsafe { core::hint::unreachable_unchecked() }
// }
