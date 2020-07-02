// SPDX-License-Identifier: GPL-2.0

#include <linux/kasan.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/types.h>

#include "kasan.h"

#define EXCLUDE_TAGS_NR		2

void kasan_init_tags(void)
{
	u8 exclude_tags[EXCLUDE_TAGS_NR];

	exclude_tags[0] = KASAN_VMALLOC_VALID;
	exclude_tags[1] = KASAN_VMALLOC_INVALID;

	init_tags(KASAN_TAG_MAX, exclude_tags, EXCLUDE_TAGS_NR);
}

u8 random_tag(void)
{
	return kasan_random_tag();
}

void *kasan_reset_tag(const void *addr)
{
	return reset_tag(addr);
}

void print_tags(u8 addr_tag, const void *addr)
{
	/* To be implemented and maybe moved */
}
