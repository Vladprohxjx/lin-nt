// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal fixed-base PE32+ loader for the experimental Linux NT ABI.
 *
 * The first execution profile is intentionally narrow: AMD64 Windows CUI
 * images with page-aligned file layout, no imports, no TLS, no exception
 * directory, no relocations and no CLR runtime.  This is sufficient for a
 * freestanding entry point that uses the project-local NT syscall ABI.
 */
#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/elf-randomize.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/pe.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sizes.h>
#include <linux/uaccess.h>
#include <asm/elf.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/ptrace.h>

static struct linux_binfmt pe_format;

static int pe_read(struct file *file, void *buf, size_t size, u64 offset)
{
	loff_t pos = offset;
	ssize_t n = kernel_read(file, buf, size, &pos);

	if (n < 0)
		return n;
	return n == size ? 0 : -ENOEXEC;
}

static int pe_validate_sections(struct file *file, u64 file_size,
				const struct pe_hdr *pe,
				const struct pe32plus_opt_hdr *opt,
				u64 section_offset,
				struct section_header **result)
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
		u64 raw_end = 0, virtual_end = 0, extent;
		u64 aligned_extent;

		ret = pe_read(file, &sections[i], sizeof(*sections),
			      section_offset + i * sizeof(*sections));
		if (ret)
			goto out;

		extent = max_t(u32, sections[i].virtual_size,
			       sections[i].raw_data_size);
		if (!extent ||
		    check_add_overflow(extent, (u64)opt->section_align - 1,
				       &aligned_extent)) {
			ret = -ENOEXEC;
			goto out;
		}
		aligned_extent &= ~((u64)opt->section_align - 1);
		if (check_add_overflow((u64)sections[i].virtual_address,
				       aligned_extent, &virtual_end) ||
		    virtual_end > opt->image_size ||
		    sections[i].virtual_address < opt->header_size ||
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

		/* The first loader requires page-granular, W^X section mappings. */
		if (!IS_ALIGNED(sections[i].virtual_address, PAGE_SIZE) ||
		    (sections[i].raw_data_size &&
		     (!IS_ALIGNED(sections[i].data_addr, PAGE_SIZE) ||
		      !IS_ALIGNED(sections[i].raw_data_size, PAGE_SIZE))) ||
		    ((sections[i].flags & IMAGE_SCN_MEM_WRITE) &&
		     (sections[i].flags & IMAGE_SCN_MEM_EXECUTE))) {
			ret = -ENOEXEC;
			goto out;
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

		if (!(sections[i].flags & IMAGE_SCN_MEM_EXECUTE))
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
	if (!ret)
		*result = sections;
	else
		kfree(sections);
	return ret;

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
			       &dir_offset) ||
	    opt->data_dirs > available / sizeof(dir) ||
	    opt->data_dirs > sizeof(struct data_directory) / sizeof(dir))
		return -ENOEXEC;

	for (i = 0; i < opt->data_dirs; i++) {
		if (check_add_overflow(dir_offset, (u64)i * sizeof(dir),
				       &offset) ||
		    pe_read(file, &dir, sizeof(dir), offset))
			return -ENOEXEC;
		if (!dir.virtual_address && !dir.size)
			continue;
		if (!dir.virtual_address || !dir.size)
			return -ENOEXEC;

		/* No imports, x64 unwind metadata, relocations, TLS, or CLR yet. */
		switch (i) {
		case 1:  /* imports */
		case 3:  /* exception directory */
		case 5:  /* base relocations */
		case 9:  /* TLS */
		case 10: /* load config / CFG */
		case 11: /* bound imports */
		case 12: /* import address table */
		case 13: /* delay imports */
		case 14: /* CLR */
			return -ENOEXEC;
		}

		/* The certificate directory uses a file offset, not an RVA. */
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

static unsigned long pe_section_prot(const struct section_header *section)
{
	unsigned long prot = 0;

	if (section->flags & IMAGE_SCN_MEM_READ)
		prot |= PROT_READ;
	if (section->flags & IMAGE_SCN_MEM_WRITE)
		prot |= PROT_WRITE;
	if (section->flags & IMAGE_SCN_MEM_EXECUTE)
		prot |= PROT_EXEC;
	return prot;
}

static int pe_map_image(struct file *file, unsigned long image_base,
			const struct pe32plus_opt_hdr *opt,
			const struct section_header *sections,
			unsigned int nr_sections)
{
	unsigned long address;
	unsigned int i;

	address = vm_mmap(file, image_base, opt->header_size, PROT_READ,
			  MAP_PRIVATE | MAP_FIXED_NOREPLACE, 0);
	if (IS_ERR_VALUE(address))
		return (long)address;
	if (address != image_base)
		return -EEXIST;

	for (i = 0; i < nr_sections; i++) {
		const struct section_header *section = &sections[i];
		unsigned long extent = max(section->virtual_size,
					   section->raw_data_size);
		unsigned long section_addr = image_base +
					     section->virtual_address;
		unsigned long prot = pe_section_prot(section);
		unsigned long mapped;

		if (section->raw_data_size) {
			mapped = vm_mmap(file, section_addr,
					 section->raw_data_size, prot,
					 MAP_PRIVATE | MAP_FIXED_NOREPLACE,
					 section->data_addr);
			if (IS_ERR_VALUE(mapped))
				return (long)mapped;
			if (mapped != section_addr)
				return -EEXIST;
		}

		/*
		 * Anonymous mappings are zero-filled.  Mapping the virtual tail
		 * separately provides PE .bss without exposing file padding.
		 */
		if (extent > section->raw_data_size) {
			unsigned long tail_addr = section_addr +
						  section->raw_data_size;
			unsigned long tail_size = PAGE_ALIGN(extent) -
						  section->raw_data_size;

			mapped = vm_mmap(NULL, tail_addr, tail_size, prot,
					 MAP_PRIVATE | MAP_ANONYMOUS |
					 MAP_FIXED_NOREPLACE, 0);
			if (IS_ERR_VALUE(mapped))
				return (long)mapped;
			if (mapped != tail_addr)
				return -EEXIST;
		}
	}
	return 0;
}

static int load_pe_binary(struct linux_binprm *bprm)
{
	struct section_header *sections = NULL;
	struct pt_regs *regs;
	struct mz_hdr mz;
	struct pe_hdr pe;
	struct pe32plus_opt_hdr opt;
	u64 file_size, pe_offset, optional_offset, section_offset;
	unsigned long image_base, image_end, entry, stack;
	unsigned long start_code = ULONG_MAX, end_code = 0;
	unsigned long start_data = ULONG_MAX, end_data = 0;
	unsigned int i;
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
	    (pe.flags & IMAGE_FILE_DLL) || !pe.sections || pe.sections > 96)
		return -ENOEXEC;

	if (pe.opt_hdr_size < sizeof(opt) ||
	    check_add_overflow(pe_offset, (u64)sizeof(pe), &optional_offset) ||
	    check_add_overflow(optional_offset, (u64)pe.opt_hdr_size,
			       &section_offset))
		return -ENOEXEC;
	ret = pe_read(bprm->file, &opt, sizeof(opt), optional_offset);
	if (ret || opt.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
	    opt.subsys != IMAGE_SUBSYSTEM_WINDOWS_CUI ||
	    !opt.image_size || !opt.header_size ||
	    opt.header_size > opt.image_size ||
	    opt.image_size > SZ_1G ||
	    opt.header_size > file_size || opt.header_size < section_offset +
	    (u64)pe.sections * sizeof(*sections) ||
	    !opt.entry_point || opt.entry_point >= opt.image_size ||
	    !is_power_of_2(opt.section_align) ||
	    !is_power_of_2(opt.file_align) ||
	    opt.section_align < PAGE_SIZE ||
	    opt.section_align > SZ_2M ||
	    opt.section_align < opt.file_align ||
	    !IS_ALIGNED(opt.section_align, PAGE_SIZE) ||
	    opt.file_align != PAGE_SIZE ||
	    (opt.dll_flags & (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
			      IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)) ||
	    !IS_ALIGNED(opt.image_size, PAGE_SIZE) ||
	    !IS_ALIGNED(opt.header_size, PAGE_SIZE))
		return -ENOEXEC;

	ret = pe_validate_sections(bprm->file, file_size, &pe, &opt,
				   section_offset, &sections);
	if (ret)
		return ret;
	ret = pe_validate_directories(bprm->file, &pe, &opt,
				      optional_offset);
	if (ret)
		goto out;

	image_base = opt.image_base;
	if (!IS_ALIGNED(image_base, PAGE_SIZE) ||
	    image_base < PAGE_SIZE ||
	    check_add_overflow(image_base, (unsigned long)opt.image_size,
			       &image_end) ||
	    image_end >= TASK_SIZE_MAX) {
		ret = -ENOEXEC;
		goto out;
	}
	entry = image_base + opt.entry_point;
	if (entry >= image_end) {
		ret = -ENOEXEC;
		goto out;
	}

	/*
	 * All format and address checks happen before begin_new_exec().  From
	 * this point onward errors are fatal to the execing task, just as for
	 * the ELF loader.
	 */
	ret = begin_new_exec(bprm);
	if (ret)
		goto out;
	set_personality_64bit();
	setup_new_exec(bprm);
	ret = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
			      EXSTACK_DISABLE_X);
	if (ret < 0)
		goto out;

	ret = pe_map_image(bprm->file, image_base, &opt, sections, pe.sections);
	if (ret)
		goto out;

	for (i = 0; i < pe.sections; i++) {
		unsigned long begin = image_base + sections[i].virtual_address;
		unsigned long end = begin +
			PAGE_ALIGN(max(sections[i].virtual_size,
				       sections[i].raw_data_size));

		if (sections[i].flags & IMAGE_SCN_MEM_EXECUTE) {
			start_code = min(start_code, begin);
			end_code = max(end_code, end);
		} else if (sections[i].flags & IMAGE_SCN_MEM_WRITE) {
			start_data = min(start_data, begin);
			end_data = max(end_data, end);
		}
	}

	current->mm->start_code = start_code == ULONG_MAX ? image_base :
							       start_code;
	current->mm->end_code = end_code;
	current->mm->start_data = start_data == ULONG_MAX ? image_base :
							       start_data;
	current->mm->end_data = end_data;
	current->mm->start_brk = current->mm->brk = image_end;

	/*
	 * The entry point is a freestanding Windows-x64 ABI entry.  Reserve
	 * the mandatory 32-byte home area and a synthetic return slot.  The
	 * initial program is required not to return from its entry point.
	 */
	stack = (bprm->p & ~0xfUL) - 40;
	if (put_user(0UL, (unsigned long __user *)stack)) {
		ret = -EFAULT;
		goto out;
	}
	current->mm->start_stack = stack;

	set_binfmt(&pe_format);
	finalize_exec(bprm);
	regs = current_pt_regs();
#ifdef ELF_PLAT_INIT
	ELF_PLAT_INIT(regs, 0);
#endif
	start_thread(regs, entry, stack);
	current->flags |= PF_WINDOWS_NT;
	ret = 0;
out:
	kfree(sections);
	return ret;
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

MODULE_DESCRIPTION("Minimal fixed-base PE32+ executable loader");
MODULE_LICENSE("GPL");
