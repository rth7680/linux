/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_MMAN_H__
#define __ASM_MMAN_H__

#include <uapi/asm/mman.h>

#define arch_calc_vm_prot_bits(prot, pkey) arm64_calc_vm_prot_bits(prot)
static inline unsigned long arm64_calc_vm_prot_bits(unsigned long prot)
{
	if (system_supports_bti() && (prot & PROT_BTI_GUARDED))
		return VM_ARM64_GP;

	return 0;
}

#define arch_vm_get_page_prot(vm_flags) arm64_vm_get_page_prot(vm_flags)
static inline pgprot_t arm64_vm_get_page_prot(unsigned long vm_flags)
{
	return (vm_flags & VM_ARM64_GP) ? __pgprot(PTE_GP) : __pgprot(0);
}

#define arch_validate_prot(prot, addr) arm64_validate_prot(prot, addr)
static inline int arm64_validate_prot(unsigned long prot, unsigned long addr)
{
	unsigned long supported = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM;

	if (system_supports_bti())
		supported |= PROT_BTI_GUARDED;

	return (prot & ~supported) == 0;
}

#endif /* ! __ASM_MMAN_H__ */
