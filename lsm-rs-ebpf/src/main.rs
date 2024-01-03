#![no_std]
#![no_main]

mod vmlinux;

use aya_bpf::{
    cty::{c_int, c_long, c_void},
    macros::{lsm, map},
    programs::LsmContext,
    helpers::bpf_probe_read_kernel_str_bytes,
    maps::{PerCpuArray, PerfEventArray},
};
use aya_log_ebpf::info;
use vmlinux::linux_binprm;
use lsm_rs_common::{EventType, Event};

#[map]
static mut SCRATCH: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[map]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::with_max_entries(0, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match unsafe { try_bprm_check_security(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn submit_event(ctx: &LsmContext, filename: &[u8; 128], dev: u32, ino: u64) -> Result<i32, i32> {
    let buf_ptr = SCRATCH.get_ptr_mut(0).ok_or(-1)?;
    let event: &mut Event = &mut *buf_ptr;

    event.etype = EventType::Exec;
    event.path = *filename;
    event.dev = dev;
    event.inode = ino;

    EVENTS.output(ctx, event, 0);

    Ok(0)
}

unsafe fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm: *const linux_binprm = ctx.arg(0);

    let dev: u32 = (*(*(*bprm).file).f_inode).i_rdev;
    let ino: u64 = (*(*(*bprm).file).f_inode).i_ino;
    let mut filename: [u8; 128] = [0u8; 128];
    let path = unsafe {
        core::str::from_utf8_unchecked(
            bpf_probe_read_kernel_str_bytes((*bprm).filename as *const u8, &mut filename)
                .map_err(|e| e as i32)?
        )
    };
    filename[127] = 0;

    submit_event(&ctx, &filename, dev, ino);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
