/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Freestanding AMD64 PE entry point for the project's restricted NT ABI.
 * No CRT, imports, TLS, stack frame, or unwind metadata are required.
 */

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

	/* Exit with status 0 on success, 1 if the console write failed. */
	testl %eax, %eax
	setne %dl
	movzbl %dl, %edx
	movl $6, %eax
	movq $-1, %r10
	syscall

	/* NtTerminateProcess is non-returning. */
	ud2

	.section .rdata,"dr"
hello_message:
	.ascii "Hello, world!\r\n"

	.section .note.GNU-stack,"",@progbits
