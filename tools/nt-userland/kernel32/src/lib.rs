#![no_std]

use core::arch::asm;

const LINUX_NT_SYS_NT_CLOSE: u64 = 5;

#[inline(always)]
unsafe fn nt_close(handle: usize) -> u32 {
    let result: u64;

    asm!(
        "syscall",
        inlateout("rax") LINUX_NT_SYS_NT_CLOSE => result,
        in("r10") handle,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );

    result as u32
}

#[no_mangle]
pub extern "system" fn GetCurrentProcess() -> isize {
    -1
}

#[no_mangle]
pub unsafe extern "system" fn CloseHandle(handle: isize) -> i32 {
    (nt_close(handle as usize) == 0) as i32
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
