// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 ARM Ltd.
 */
#include <linux/mm.h>
#include <linux/vmalloc.h>

pgprot_t arm64_calc_vmalloc_prot_bits(pgprot_t prot)
{
	if (IS_ENABLED(CONFIG_ARM64_MTE) &&
			(pgprot_val(prot) == pgprot_val(PAGE_KERNEL)))
		prot = PAGE_KERNEL_TAGGED;

	return prot;
}
