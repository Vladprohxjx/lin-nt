// SPDX-License-Identifier: GPL-2.0-only
/*
 * Experimental Windows NT syscall ABI dispatcher.
 *
 * The syscall numbers here form a project-local ABI for the matching NT
 * runtime.  They intentionally do not claim compatibility with Microsoft's
 * build-specific system service tables.  Individual services will be added
 * only when their argument marshalling and object semantics are implemented.
 */

#include <linux/kernel.h>
#include <linux/ntsyscall.h>
#include <linux/nospec.h>
#include <linux/types.h>
#include <uapi/linux/ntsyscall.h>

typedef u32 (*nt_syscall_fn_t)(struct pt_regs *regs);

static u32 nt_syscall_unimplemented(struct pt_regs *regs)
{
	(void)regs;
	return LINUX_NT_STATUS_NOT_IMPLEMENTED;
}

static const nt_syscall_fn_t nt_syscall_table[LINUX_NT_SYS_MAX] = {
	[LINUX_NT_SYS_NtAllocateVirtualMemory] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtFreeVirtualMemory] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtCreateFile] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtReadFile] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtWriteFile] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtClose] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtTerminateProcess] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtQuerySystemInformation] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtUserDrawFrame] = nt_syscall_unimplemented,
};

long do_nt_syscall(struct pt_regs *regs, unsigned long nr)
{
	u32 status;

	if (nr >= ARRAY_SIZE(nt_syscall_table)) {
		status = LINUX_NT_STATUS_INVALID_SYSTEM_SERVICE;
	} else {
		nr = array_index_nospec(nr, ARRAY_SIZE(nt_syscall_table));
		status = nt_syscall_table[nr](regs);
	}

	/* NTSTATUS is a 32-bit value in EAX, zero-extended in RAX. */
	return (long)status;
}
