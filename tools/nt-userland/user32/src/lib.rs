#![no_std]

use core::arch::asm;

const LINUX_NT_SYS_NT_USER_DRAW_FRAME: u64 = 8;

#[no_mangle]
pub unsafe extern "system" fn DrawFrame(
    framebuffer: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
) -> u32 {
    let result: u64;

    asm!(
        "syscall",
        inlateout("rax") LINUX_NT_SYS_NT_USER_DRAW_FRAME => result,
        in("r10") framebuffer as usize,
        in("rdx") width as usize,
        in("r8") height as usize,
        in("r9") stride as usize,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );

    result as u32
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
