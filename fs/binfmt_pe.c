// SPDX-License-Identifier: GPL-2.0-only
/*
 * Experimental PE32+ image recognizer.
 *
 * This is deliberately not an executable PE loader yet: mapping PE sections,
 * relocations, imports, the initial NT process environment and the syscall
 * ABI must be implemented before a PE image can safely be entered.
 */

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/pe.h>

static int load_pe_binary(struct linux_binprm *bprm)
{
	struct mz_hdr mz;
	struct pe_hdr pe;
	struct pe32plus_opt_hdr opt;
	u64 file_size, pe_offset, section_offset, section_bytes, end;
	loff_t pos;
	ssize_t n;

	if (!bprm->file)
		return -ENOEXEC;

	file_size = i_size_read(file_inode(bprm->file));
	if (file_size < sizeof(mz))
		return -ENOEXEC;

	pos = 0;
	n = kernel_read(bprm->file, &mz, sizeof(mz), &pos);
	if (n != sizeof(mz) || mz.magic != IMAGE_DOS_SIGNATURE)
		return -ENOEXEC;

	pe_offset = mz.peaddr;
	if (pe_offset > file_size ||
	    file_size - pe_offset < sizeof(pe))
		return -ENOEXEC;

	pos = pe_offset;
	n = kernel_read(bprm->file, &pe, sizeof(pe), &pos);
	if (n != sizeof(pe) || pe.magic != IMAGE_NT_SIGNATURE ||
	    pe.machine != IMAGE_FILE_MACHINE_AMD64 ||
	    !pe.sections || pe.sections > 96)
		return -ENOEXEC;

	if (pe.opt_hdr_size < sizeof(opt))
		return -ENOEXEC;

	if (check_add_overflow(pe_offset, (u64)sizeof(pe), &section_offset) ||
	    check_add_overflow(section_offset, (u64)pe.opt_hdr_size,
			       &section_offset) ||
	    check_mul_overflow((u64)pe.sections,
			       (u64)sizeof(struct section_header),
			       &section_bytes) ||
	    check_add_overflow(section_offset, section_bytes, &end) ||
	    end > file_size)
		return -ENOEXEC;

	pos = pe_offset + sizeof(pe);
	n = kernel_read(bprm->file, &opt, sizeof(opt), &pos);
	if (n != sizeof(opt) ||
	    opt.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
	    !opt.image_size || !opt.header_size ||
	    opt.header_size > opt.image_size ||
	    opt.entry_point >= opt.image_size)
		return -ENOEXEC;

	/*
	 * Header recognition only.  Do not call begin_new_exec() until a
	 * complete image mapper and NT process bootstrap are available.
	 */
	return -ENOEXEC;
}

static struct linux_binfmt pe_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_pe_binary,
};

static int __init init_pe_binfmt(void)
{
	register_binfmt(&pe_format);
	return 0;
}

static void __exit exit_pe_binfmt(void)
{
	unregister_binfmt(&pe_format);
}

core_initcall(init_pe_binfmt);
module_exit(exit_pe_binfmt);

MODULE_DESCRIPTION("Experimental PE32+ image format recognizer");
MODULE_LICENSE("GPL");
