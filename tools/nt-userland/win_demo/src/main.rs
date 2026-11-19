#![no_std]
#![no_main]

use core::arch::asm;

const LINUX_NT_SYS_NT_USER_DRAW_FRAME: u64 = 8;

#[no_mangle]
pub extern "system" fn mainCRTStartup() -> ! {
    unsafe {
        let result: u64;

        asm!(
            "syscall",
            inlateout("rax") LINUX_NT_SYS_NT_USER_DRAW_FRAME => result,
            in("r10") 0usize,
            in("rdx") 0usize,
            in("r8") 0usize,
            in("r9") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );

        let _ = result;
    }

    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
