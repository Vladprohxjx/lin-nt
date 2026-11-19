// SPDX-License-Identifier: GPL-2.0-only
/*
 * Experimental Windows NT syscall ABI dispatcher.
 *
 * The syscall numbers here form a project-local ABI for the matching NT
 * runtime.  They intentionally do not claim compatibility with Microsoft's
 * build-specific system service tables.  Only the documented minimal
 * services are implemented; all other entries return NOT_IMPLEMENTED.
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/ntsyscall.h>
#include <linux/nospec.h>
#include <linux/types.h>
#include <uapi/linux/ntsyscall.h>
#include <asm/ptrace.h>

typedef u32 (*nt_syscall_fn_t)(struct pt_regs *regs);

static u32 nt_syscall_terminate_process(struct pt_regs *regs)
{
	/* Only the current-process pseudo handle is supported in this ABI. */
	if (regs->r10 != (unsigned long)-1)
		return LINUX_NT_STATUS_INVALID_HANDLE;

	do_group_exit((int)(regs->dx & 0xff) << 8);
	return LINUX_NT_STATUS_SUCCESS;
}

static u32 nt_syscall_write_console(struct pt_regs *regs)
{
	struct fd f;
	struct file *file;
	size_t len = regs->r8;
	loff_t *pos;
	ssize_t written;

	if (!len || len > PAGE_SIZE || !regs->dx ||
	    regs->r10 > INT_MAX)
		return LINUX_NT_STATUS_INVALID_PARAMETER;

	f = fdget_pos((unsigned int)regs->r10);
	if (fd_empty(f))
		return LINUX_NT_STATUS_INVALID_HANDLE;
	file = fd_file(f);
	if (!(file->f_mode & FMODE_WRITE) ||
	    !(file->f_mode & FMODE_CAN_WRITE) ||
	    !S_ISCHR(file_inode(file)->i_mode)) {
		fdput_pos(f);
		return LINUX_NT_STATUS_INVALID_HANDLE;
	}

	/* vfs_write performs access_ok() and copies from the caller's buffer. */
	pos = (file->f_mode & FMODE_STREAM) ? NULL : &file->f_pos;
	written = vfs_write(file, (const char __user *)regs->dx, len, pos);
	fdput_pos(f);

	if (written == len)
		return LINUX_NT_STATUS_SUCCESS;
	if (written == -EFAULT)
		return LINUX_NT_STATUS_ACCESS_VIOLATION;
	return LINUX_NT_STATUS_UNSUCCESSFUL;
}

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
	[LINUX_NT_SYS_NtTerminateProcess] = nt_syscall_terminate_process,
	[LINUX_NT_SYS_NtQuerySystemInformation] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtUserDrawFrame] = nt_syscall_unimplemented,
	[LINUX_NT_SYS_NtWriteConsole] = nt_syscall_write_console,
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
