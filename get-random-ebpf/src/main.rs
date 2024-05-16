#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint}, maps::PerfEventArray, programs::TracePointContext, EbpfContext
};
use aya_log_ebpf::info;
use get_random_common::Event;

#[map]
static mut EVENTS: PerfEventArray<Event> = PerfEventArray::new(0);


#[tracepoint]
pub fn get_random(ctx: TracePointContext) -> u32 {
    match try_get_random( ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_get_random( ctx: TracePointContext) -> Result<u32, u32> {
    let data = Event{
        pid : ctx.pid(),
        uid : ctx.uid(),
    };
    unsafe { EVENTS.output(&ctx, &data, 0) };
    //info!(&ctx, "tracepoint sys_enter_getrandom called from process");
    Ok(0)
}


#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
