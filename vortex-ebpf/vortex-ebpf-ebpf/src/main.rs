#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

#[xdp]
pub fn vortex_ebpf(ctx: XdpContext) -> u32 {
    match try_vortex_ebpf(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_vortex_ebpf(ctx: XdpContext) -> Result<u32, u32> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    if data + 14 + 20 > data_end {
        return Err(1);
    }

    let eth_proto = unsafe { *(data as *const u16).add(12) };
    if eth_proto != 0x0800u16.to_be() {
        return Ok(xdp_action::XDP_PASS);
    }

    let ihl = unsafe { *((data + 14) as *const u8) & 0x0f } as usize;
    let ip_header_len = ihl * 4;
    if ip_header_len < 20 || data + 14 + ip_header_len > data_end {
        return Err(2);
    }

    let ip_proto = unsafe { *((data + 14 + 9) as *const u8) };
    if ip_proto != 6u8 {
        return Ok(xdp_action::XDP_PASS);
    }

    info!(&ctx, "tcp packet observed");
    Ok(xdp_action::XDP_DROP)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
