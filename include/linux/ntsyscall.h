/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NTSYSCALL_H
#define _LINUX_NTSYSCALL_H

struct pt_regs;

long do_nt_syscall(struct pt_regs *regs, unsigned long nr);

#endif /* _LINUX_NTSYSCALL_H */
