/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MTE_HELPERS_H
#define __ASM_MTE_HELPERS_H

#include <linux/bits.h>

#define MTE_TAG_SHIFT		56
#define MTE_TAG_SIZE		4
#define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
#define MTE_TAG_MAX		(MTE_TAG_MASK >> MTE_TAG_SHIFT)
#define MTE_TAG_MAX_MASK	GENMASK(MTE_TAG_MAX, 0)

#ifndef __ASSEMBLY__

#ifdef CONFIG_ARM64_MTE
#include <linux/bitfield.h>
#include <linux/types.h>

#define mte_get_ptr_tag(ptr) \
		((u8)(FIELD_GET(MTE_TAG_MASK, (u64)ptr)))

void *mte_get_tagged_addr(void *src);
void *mte_set_mem_tag_range(void *address, size_t size,
			    u8 tag, bool ignore_tag);
void mte_set_tag_range(void *addr, size_t size);
u8 mte_random_tag(void);
u64 mte_get_random_tag(void);
void mte_init_tags(u64 max_tags);
#else
#define mte_get_ptr_tag(ptr)		0xf

static inline void *mte_get_tagged_addr(void *src)
{
	return src;
}
#endif /* CONFIG_ARM64_MTE */

#endif /* __ASSEMBLY__ */
#endif /* __ASM_MTE_HELPERS_H  */
