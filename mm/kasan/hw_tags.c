// SPDX-License-Identifier: GPL-2.0

#include <linux/kasan.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/types.h>

#include "kasan.h"

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
