/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Extract an ELF file's .note.gnu.property.
 *
 * The path from the ELF header to the note section is the following:
 * elfhdr->elf_phdr->elf_note->property[].
 */

#include <uapi/linux/elf-em.h>
#include <linux/processor.h>
#include <linux/binfmts.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/compat.h>

/*
 * The .note.gnu.property layout:
 *
 *	struct elf_note {
 *		u32 n_namesz; --> sizeof(n_name[]); always (4)
 *		u32 n_ndescsz;--> sizeof(property[])
 *		u32 n_type;   --> always NT_GNU_PROPERTY_TYPE_0
 *	};
 *	char n_name[4]; --> always 'GNU\0'
 *
 *	struct {
 *		struct gnu_property {
 *			u32 pr_type;
 *			u32 pr_datasz;
 *		};
 *		u8 pr_data[pr_datasz];
 *	}[];
 */

#define BUF_SIZE (PAGE_SIZE / 4)

struct gnu_property {
	u32 pr_type;
	u32 pr_datasz;
};

typedef bool (test_item_fn)(void *buf, u32 *arg, u32 type);
typedef void *(next_item_fn)(void *buf, u32 *arg, u32 type);

static inline bool test_note_type(void *buf, u32 *align, u32 note_type)
{
	struct elf_note *n = buf;

	return ((n->n_type == note_type) && (n->n_namesz == 4) &&
		(memcmp(n + 1, "GNU", 4) == 0));
}

static inline void *next_note(void *buf, u32 *align, u32 note_type)
{
	struct elf_note *n = buf;
	u64 size;

	if (check_add_overflow((u64)sizeof(*n), (u64)n->n_namesz, &size))
		return NULL;

	size = round_up(size, *align);

	if (check_add_overflow(size, (u64)n->n_descsz, &size))
		return NULL;

	size = round_up(size, *align);

	if (buf + size < buf)
		return NULL;
	else
		return (buf + size);
}

static inline bool test_property(void *buf, u32 *max_type, u32 pr_type)
{
	struct gnu_property *pr = buf;

	/*
	 * Property types must be in ascending order.
	 * Keep track of the max when testing each.
	 */
	if (pr->pr_type > *max_type)
		*max_type = pr->pr_type;

	return (pr->pr_type == pr_type);
}

static inline void *next_property(void *buf, u32 *max_type, u32 pr_type)
{
	struct gnu_property *pr = buf;

	if ((buf + sizeof(*pr) +  pr->pr_datasz < buf) ||
	    (pr->pr_type > pr_type) ||
	    (pr->pr_type > *max_type))
		return NULL;
	else
		return (buf + sizeof(*pr) + pr->pr_datasz);
}

/*
 * Scan 'buf' for a pattern; return true if found.
 * *pos is the distance from the beginning of buf to where
 * the searched item or the next item is located.
 */
static int scan(u8 *buf, u32 buf_size, int item_size, test_item_fn test_item,
		next_item_fn next_item, u32 *arg, u32 type, u32 *pos)
{
	int found = 0;
	u8 *p, *max;

	max = buf + buf_size;
	if (max < buf)
		return 0;

	p = buf;

	while ((p + item_size < max) && (p + item_size > buf)) {
		if (test_item(p, arg, type)) {
			found = 1;
			break;
		}

		p = next_item(p, arg, type);
	}

	*pos = (p + item_size <= buf) ? 0 : (u32)(p - buf);
	return found;
}

/*
 * Search an NT_GNU_PROPERTY_TYPE_0 for the property of 'pr_type'.
 */
static int find_property(struct file *file, unsigned long desc_size,
			 loff_t file_offset, u8 *buf,
			 u32 pr_type, u32 *property)
{
	u32 buf_pos;
	unsigned long read_size;
	unsigned long done;
	int found = 0;
	int ret = 0;
	u32 last_pr = 0;

	*property = 0;
	buf_pos = 0;

	for (done = 0; done < desc_size; done += buf_pos) {
		read_size = desc_size - done;
		if (read_size > BUF_SIZE)
			read_size = BUF_SIZE;

		ret = kernel_read(file, buf, read_size, &file_offset);

		if (ret != read_size)
			return (ret < 0) ? ret : -EIO;

		ret = 0;
		found = scan(buf, read_size, sizeof(struct gnu_property),
			     test_property, next_property,
			     &last_pr, pr_type, &buf_pos);

		if ((!buf_pos) || found)
			break;

		file_offset += buf_pos - read_size;
	}

	if (found) {
		struct gnu_property *pr =
			(struct gnu_property *)(buf + buf_pos);

		if (pr->pr_datasz == 4) {
			u32 *max =  (u32 *)(buf + read_size);
			u32 *data = (u32 *)((u8 *)pr + sizeof(*pr));

			if (data + 1 <= max) {
				*property = *data;
			} else {
				file_offset += buf_pos - read_size;
				file_offset += sizeof(*pr);
				ret = kernel_read(file, property, 4,
						  &file_offset);
			}
		}
	}

	return ret;
}

/*
 * Search a PT_NOTE segment for NT_GNU_PROPERTY_TYPE_0.
 */
static int find_note_type_0(struct file *file, loff_t file_offset,
			    unsigned long note_size, u32 align,
			    u32 pr_type, u32 *property)
{
	u8 *buf;
	u32 buf_pos;
	unsigned long read_size;
	unsigned long done;
	int found = 0;
	int ret = 0;

	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	*property = 0;
	buf_pos = 0;

	for (done = 0; done < note_size; done += buf_pos) {
		read_size = note_size - done;
		if (read_size > BUF_SIZE)
			read_size = BUF_SIZE;

		ret = kernel_read(file, buf, read_size, &file_offset);

		if (ret != read_size) {
			ret = (ret < 0) ? ret : -EIO;
			kfree(buf);
			return ret;
		}

		/*
		 * item_size = sizeof(struct elf_note) + elf_note.n_namesz.
		 * n_namesz is 4 for the note type we look for.
		 */
		ret = scan(buf, read_size, sizeof(struct elf_note) + 4,
			      test_note_type, next_note,
			      &align, NT_GNU_PROPERTY_TYPE_0, &buf_pos);

		file_offset += buf_pos - read_size;

		if (ret && !found) {
			struct elf_note *n =
				(struct elf_note *)(buf + buf_pos);
			u64 start = round_up(sizeof(*n) + n->n_namesz, align);
			u64 total = 0;

			if (check_add_overflow(start, (u64)n->n_descsz, &total)) {
				ret = -EINVAL;
				break;
			}
			total = round_up(total, align);

			ret = find_property(file, n->n_descsz,
					    file_offset + start,
					    buf, pr_type, property);
			found++;
			file_offset += total;
			buf_pos += total;
		} else if (!buf_pos || ret) {
			ret = 0;
			*property = 0;
			break;
		}
	}

	kfree(buf);
	return ret;
}

/*
 * Look at an ELF file's PT_NOTE segments, then NT_GNU_PROPERTY_TYPE_0, then
 * the property of pr_type.
 *
 * Input:
 *	file: the file to search;
 *	phdr: the file's elf header;
 *	phnum: number of entries in phdr;
 *	pr_type: the property type.
 *
 * Output:
 *	The property found.
 *
 * Return:
 *	Zero or error.
 */
static int scan_segments_64(struct file *file, struct elf64_phdr *phdr,
			    int phnum, u32 pr_type, u32 *property)
{
	int i;
	int err = 0;

	for (i = 0; i < phnum; i++, phdr++) {
		if ((phdr->p_type != PT_NOTE) || (phdr->p_align != 8))
			continue;

		/*
		 * Search the PT_NOTE segment for NT_GNU_PROPERTY_TYPE_0.
		 */
		err = find_note_type_0(file, phdr->p_offset, phdr->p_filesz,
				       phdr->p_align, pr_type, property);
		if (err)
			return err;
	}

	return 0;
}

#ifdef CONFIG_COMPAT
static int scan_segments_32(struct file *file, struct elf32_phdr *phdr,
			    int phnum, u32 pr_type, u32 *property)
{
	int i;
	int err = 0;

	for (i = 0; i < phnum; i++, phdr++) {
		if ((phdr->p_type != PT_NOTE) || (phdr->p_align != 4))
			continue;

		/*
		 * Search the PT_NOTE segment for NT_GNU_PROPERTY_TYPE_0.
		 */
		err = find_note_type_0(file, phdr->p_offset, phdr->p_filesz,
				       phdr->p_align, pr_type, property);
		if (err)
			return err;
	}

	return 0;
}
#endif

int get_gnu_property(void *ehdr_p, void *phdr_p, struct file *f,
		     u32 pr_type, u32 *property)
{
	struct elf64_hdr *ehdr64 = ehdr_p;
	int err = 0;

	*property = 0;

	if (ehdr64->e_ident[EI_CLASS] == ELFCLASS64) {
		struct elf64_phdr *phdr64 = phdr_p;

		err = scan_segments_64(f, phdr64, ehdr64->e_phnum,
				       pr_type, property);
		if (err < 0)
			goto out;
	} else {
#ifdef CONFIG_COMPAT
		struct elf32_hdr *ehdr32 = ehdr_p;

		if (ehdr32->e_ident[EI_CLASS] == ELFCLASS32) {
			struct elf32_phdr *phdr32 = phdr_p;

			err = scan_segments_32(f, phdr32, ehdr32->e_phnum,
					       pr_type, property);
			if (err < 0)
				goto out;
		}
#else
	WARN_ONCE(1, "Exec of 32-bit app, but CONFIG_COMPAT is not enabled.\n");
	return -ENOTSUPP;
#endif
	}

out:
	return err;
}
