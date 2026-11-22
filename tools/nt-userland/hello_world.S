/* Minimal freestanding AMD64 PE entry point for lin-nt. */
.text
.globl mainCRTStartup
.def mainCRTStartup; .scl 2; .type 32; .endef
.p2align 4
mainCRTStartup:
    /* NtWriteConsole(fd=1, buffer=hello_message, length=15). */
    movl $9, %eax
    movl $1, %r10d
    leaq hello_message(%rip), %rdx
    movl $15, %r8d
    syscall

    /* NtTerminateProcess(status = write failure ? 1 : 0). */
    testl %eax, %eax
    setne %dl
    movzbl %dl, %edx
    movl $6, %eax
    movq $-1, %r10
    syscall
    ud2

.section .rdata,"dr"
hello_message:
    .ascii "Hello, world!\r\n"
