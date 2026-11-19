/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_NTSYSCALL_H
#define _UAPI_LINUX_NTSYSCALL_H

/*
 * Stable syscall numbers for the experimental Linux NT personality.
 *
 * This is a project-local ABI for the accompanying NT runtime.  It is not
 * compatible with the build-specific syscall numbering used by Microsoft
 * Windows.  The x86-64 entry ABI follows the Windows syscall register
 * convention: argument 1 in R10, then RDX, R8 and R9; later arguments are
 * passed in the caller's stack argument area.
 */
#define LINUX_NT_SYS_NtAllocateVirtualMemory	0
#define LINUX_NT_SYS_NtFreeVirtualMemory	1
#define LINUX_NT_SYS_NtCreateFile		2
#define LINUX_NT_SYS_NtReadFile			3
#define LINUX_NT_SYS_NtWriteFile		4
#define LINUX_NT_SYS_NtClose			5
#define LINUX_NT_SYS_NtTerminateProcess		6
#define LINUX_NT_SYS_NtQuerySystemInformation	7
#define LINUX_NT_SYS_NtUserDrawFrame		8
#define LINUX_NT_SYS_NtWriteConsole		9
#define LINUX_NT_SYS_MAX			10

/* NTSTATUS values returned by the experimental dispatcher. */
#define LINUX_NT_STATUS_SUCCESS			0x00000000U
#define LINUX_NT_STATUS_NOT_IMPLEMENTED		0xc0000002U
#define LINUX_NT_STATUS_INVALID_SYSTEM_SERVICE	0xc000001cU
#define LINUX_NT_STATUS_INVALID_HANDLE		0xc0000008U
#define LINUX_NT_STATUS_INVALID_PARAMETER		0xc000000dU
#define LINUX_NT_STATUS_ACCESS_VIOLATION		0xc0000005U
#define LINUX_NT_STATUS_UNSUCCESSFUL		0xc0000001U

#endif /* _UAPI_LINUX_NTSYSCALL_H */
