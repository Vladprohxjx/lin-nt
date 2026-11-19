// SPDX-License-Identifier: GPL-2.0-only
/*
 * Experimental PE32+ image recognizer.
 *
 * This validates the on-disk image layout.  It intentionally does not enter
 * the image: section mapping, relocations, imports, the NT process environment
 * and the syscall ABI must be implemented before PE execution is safe.
 */

#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/pe.h>
#include <linux/slab.h>
#include <linux/sizes.h>

static int pe_read(struct file *file, void *buf, size_t size, u64 offset)
{
	loff_t pos = offset;
	ssize_t n;

	n = kernel_read(file, buf, size, &pos);
	if (n < 0)
		return n;
	return n == size ? 0 : -ENOEXEC;
}

static int pe_validate_sections(struct file *file, u64 file_size,
				const struct pe_hdr *pe,
				const struct pe32plus_opt_hdr *opt,
				u64 section_offset)
{
	struct section_header *sections;
	u64 section_bytes, table_end;
	unsigned int i, j;
	int ret = -ENOEXEC;

	if (check_mul_overflow((u64)pe->sections,
			       (u64)sizeof(*sections), &section_bytes) ||
	    check_add_overflow(section_offset, section_bytes, &table_end) ||
	    table_end > file_size || opt->header_size < table_end)
		return -ENOEXEC;

	sections = kcalloc(pe->sections, sizeof(*sections), GFP_KERNEL);
	if (!sections)
		return -ENOMEM;

	for (i = 0; i < pe->sections; i++) {
		u64 raw_end, virtual_end;
		u64 extent;

		ret = pe_read(file, &sections[i], sizeof(*sections),
			      section_offset + i * sizeof(*sections));
		if (ret)
			goto out;

		extent = max_t(u32, sections[i].virtual_size,
			       sections[i].raw_data_size);
		if (extent) {
			u64 aligned_extent;

			if (check_add_overflow(extent,
					       (u64)opt->section_align - 1,
					       &aligned_extent)) {
				ret = -ENOEXEC;
				goto out;
			}
			aligned_extent &= ~((u64)opt->section_align - 1);
			if (check_add_overflow((u64)sections[i].virtual_address,
					       aligned_extent, &virtual_end) ||
			    virtual_end > opt->image_size) {
				ret = -ENOEXEC;
				goto out;
			}
		}

		if (sections[i].virtual_address < opt->header_size ||
		    !IS_ALIGNED(sections[i].virtual_address, opt->section_align)) {
			ret = -ENOEXEC;
			goto out;
		}

		if (sections[i].raw_data_size) {
			if (sections[i].data_addr < opt->header_size ||
			    !IS_ALIGNED(sections[i].data_addr, opt->file_align) ||
			    !IS_ALIGNED(sections[i].raw_data_size,
					opt->file_align) ||
			    check_add_overflow((u64)sections[i].data_addr,
					       (u64)sections[i].raw_data_size,
					       &raw_end) ||
			    raw_end > file_size) {
				ret = -ENOEXEC;
				goto out;
			}
		}

		for (j = 0; j < i; j++) {
			u64 prev_extent = max_t(u32, sections[j].virtual_size,
						sections[j].raw_data_size);
			u64 prev_end, aligned_prev_extent;

			if (sections[i].raw_data_size &&
			    sections[j].raw_data_size) {
				u64 prev_raw_end;

				if (check_add_overflow(
					    (u64)sections[j].data_addr,
					    (u64)sections[j].raw_data_size,
					    &prev_raw_end) ||
				    (sections[i].data_addr < prev_raw_end &&
				     sections[j].data_addr < raw_end)) {
					ret = -ENOEXEC;
					goto out;
				}
			}

			if (!extent || !prev_extent)
				continue;
			if (check_add_overflow(prev_extent,
					       (u64)opt->section_align - 1,
					       &aligned_prev_extent)) {
				ret = -ENOEXEC;
				goto out;
			}
			aligned_prev_extent &= ~((u64)opt->section_align - 1);
			if (check_add_overflow((u64)sections[j].virtual_address,
					       aligned_prev_extent, &prev_end) ||
			    (sections[i].virtual_address < prev_end &&
			     sections[j].virtual_address < virtual_end)) {
				ret = -ENOEXEC;
				goto out;
			}
		}
	}

	/* The entry point must be covered by an executable section. */
	ret = -ENOEXEC;
	for (i = 0; i < pe->sections; i++) {
		u64 extent = max_t(u32, sections[i].virtual_size,
				   sections[i].raw_data_size);
		u64 end;

		if (!(sections[i].flags & IMAGE_SCN_MEM_EXECUTE) || !extent)
			continue;
		if (check_add_overflow((u64)sections[i].virtual_address,
				       extent, &end))
			continue;
		if (opt->entry_point >= sections[i].virtual_address &&
		    opt->entry_point < end) {
			ret = 0;
			break;
		}
	}

out:
	kfree(sections);
	return ret;
}

static int pe_validate_directories(struct file *file,
				   const struct pe_hdr *pe,
				   const struct pe32plus_opt_hdr *opt,
				   u64 optional_offset)
{
	struct data_dirent dir;
	u64 available, dir_offset, offset, end;
	unsigned int i;

	available = pe->opt_hdr_size - sizeof(*opt);
	if (check_add_overflow(optional_offset, (u64)sizeof(*opt),
			       &dir_offset))
		return -ENOEXEC;
	if (opt->data_dirs > available / sizeof(dir) ||
	    opt->data_dirs > sizeof(struct data_directory) / sizeof(dir))
		return -ENOEXEC;

	for (i = 0; i < opt->data_dirs; i++) {
		if (check_add_overflow(dir_offset, (u64)i * sizeof(dir),
				       &offset))
			return -ENOEXEC;
		if (pe_read(file, &dir, sizeof(dir), offset))
			return -ENOEXEC;
		if (!dir.virtual_address && !dir.size)
			continue;
		if (!dir.virtual_address || !dir.size)
			return -ENOEXEC;

		/* The certificate directory is a file offset, not an RVA. */
		if (i == 4) {
			if (check_add_overflow((u64)dir.virtual_address,
					       (u64)dir.size, &end) ||
			    end > i_size_read(file_inode(file)))
				return -ENOEXEC;
			continue;
		}
		if (check_add_overflow((u64)dir.virtual_address,
				       (u64)dir.size, &end) ||
		    end > opt->image_size)
			return -ENOEXEC;
	}

	return 0;
}

static int load_pe_binary(struct linux_binprm *bprm)
{
	struct mz_hdr mz;
	struct pe_hdr pe;
	struct pe32plus_opt_hdr opt;
	u64 file_size, pe_offset, optional_offset, section_offset;
	u64 section_bytes, table_end;
	int ret;

	if (!bprm->file)
		return -ENOEXEC;

	file_size = i_size_read(file_inode(bprm->file));
	if (file_size < sizeof(mz))
		return -ENOEXEC;

	ret = pe_read(bprm->file, &mz, sizeof(mz), 0);
	if (ret || mz.magic != IMAGE_DOS_SIGNATURE)
		return -ENOEXEC;

	pe_offset = mz.peaddr;
	if (pe_offset < sizeof(mz) || pe_offset > file_size ||
	    file_size - pe_offset < sizeof(pe))
		return -ENOEXEC;

	ret = pe_read(bprm->file, &pe, sizeof(pe), pe_offset);
	if (ret || pe.magic != IMAGE_NT_SIGNATURE ||
	    pe.machine != IMAGE_FILE_MACHINE_AMD64 ||
	    !(pe.flags & IMAGE_FILE_EXECUTABLE_IMAGE) ||
	    (pe.flags & IMAGE_FILE_DLL) ||
	    !pe.sections || pe.sections > 96)
		return -ENOEXEC;

	if (pe.opt_hdr_size < sizeof(opt) ||
	    check_add_overflow(pe_offset, (u64)sizeof(pe), &optional_offset) ||
	    check_add_overflow(optional_offset, (u64)pe.opt_hdr_size,
			       &section_offset) ||
	    check_mul_overflow((u64)pe.sections,
			       (u64)sizeof(struct section_header),
			       &section_bytes) ||
	    check_add_overflow(section_offset, section_bytes, &table_end) ||
	    table_end > file_size)
		return -ENOEXEC;

	ret = pe_read(bprm->file, &opt, sizeof(opt), optional_offset);
	if (ret || opt.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
	    !opt.image_size || !opt.header_size ||
	    opt.header_size > opt.image_size ||
	    opt.header_size > file_size || opt.header_size < table_end ||
	    !opt.entry_point || opt.entry_point >= opt.image_size ||
	    !is_power_of_2(opt.section_align) ||
	    !is_power_of_2(opt.file_align) ||
	    opt.section_align > SZ_2M || opt.file_align > SZ_64K)
		return -ENOEXEC;

	if (opt.section_align < PAGE_SIZE) {
		if (opt.section_align != opt.file_align)
			return -ENOEXEC;
	} else if (opt.file_align < 512 ||
		   opt.file_align > opt.section_align) {
		return -ENOEXEC;
	}

	if (!IS_ALIGNED(opt.image_size, opt.section_align) ||
	    !IS_ALIGNED(opt.header_size, opt.file_align))
		return -ENOEXEC;

	ret = pe_validate_sections(bprm->file, file_size, &pe, &opt,
				   section_offset);
	if (ret)
		return ret;

	ret = pe_validate_directories(bprm->file, &pe, &opt, optional_offset);
	if (ret)
		return ret;

	/*
	 * Header validation only.  A valid PE must not be marked as an NT
	 * process or passed to userspace until mapping, relocations, imports,
	 * stack/TEB/PEB setup and the NT syscall ABI are available.
	 */
	return -ENOEXEC;
}

static struct linux_binfmt pe_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_pe_binary,
};

static int __init init_pe_binfmt(void)
{
	return register_binfmt(&pe_format);
}

static void __exit exit_pe_binfmt(void)
{
	unregister_binfmt(&pe_format);
}

core_initcall(init_pe_binfmt);
module_exit(exit_pe_binfmt);

MODULE_DESCRIPTION("Experimental PE32+ image format recognizer");
MODULE_LICENSE("GPL");
