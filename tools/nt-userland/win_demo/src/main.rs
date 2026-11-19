#![no_std]
#![no_main]

use core::arch::asm;

const LINUX_NT_SYS_NT_TERMINATE_PROCESS: u64 = 6;
const LINUX_NT_SYS_NT_WRITE_CONSOLE: u64 = 9;

static MESSAGE: &[u8] = b"Hello, world!\r\n";

#[no_mangle]
pub extern "system" fn mainCRTStartup() -> ! {
    let write_status: u64;

    unsafe {
        asm!(
            "syscall",
            inlateout("rax") LINUX_NT_SYS_NT_WRITE_CONSOLE => write_status,
            in("r10") 1usize,
            in("rdx") MESSAGE.as_ptr(),
            in("r8") MESSAGE.len(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );

        let exit_status = if write_status as u32 == 0 { 0usize } else { 1usize };
        asm!(
            "syscall",
            inlateout("rax") LINUX_NT_SYS_NT_TERMINATE_PROCESS => _,
            in("r10") usize::MAX,
            in("rdx") exit_status,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
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
