#![no_std]

use core::arch::asm;
use core::ffi::c_void;

const LINUX_NT_SYS_NT_CLOSE: u64 = 5;
const LINUX_NT_SYS_NT_QUERY_SYSTEM_INFORMATION: u64 = 7;
const LINUX_NT_SYS_NT_USER_DRAW_FRAME: u64 = 8;

#[inline(always)]
unsafe fn nt_syscall4(number: u64, a1: usize, a2: usize,
                      a3: usize, a4: usize) -> u32 {
    let result: u64;

    asm!(
        "syscall",
        inlateout("rax") number => result,
        in("r10") a1,
        in("rdx") a2,
        in("r8") a3,
        in("r9") a4,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );

    result as u32
}

#[no_mangle]
pub unsafe extern "system" fn NtClose(handle: usize) -> u32 {
    nt_syscall4(LINUX_NT_SYS_NT_CLOSE, handle, 0, 0, 0)
}

#[no_mangle]
pub unsafe extern "system" fn NtQuerySystemInformation(
    information_class: u32,
    information: *mut c_void,
    information_length: u32,
    return_length: *mut u32,
) -> u32 {
    nt_syscall4(
        LINUX_NT_SYS_NT_QUERY_SYSTEM_INFORMATION,
        information_class as usize,
        information as usize,
        information_length as usize,
        return_length as usize,
    )
}

#[no_mangle]
pub unsafe extern "system" fn NtUserDrawFrame(
    framebuffer: *mut u32,
    width: u32,
    height: u32,
    stride: u32,
) -> u32 {
    nt_syscall4(
        LINUX_NT_SYS_NT_USER_DRAW_FRAME,
        framebuffer as usize,
        width as usize,
        height as usize,
        stride as usize,
    )
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
