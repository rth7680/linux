#ifndef _ASM_ARM64_VMALLOC_H
#define _ASM_ARM64_VMALLOC_H

pgprot_t arm64_calc_vmalloc_prot_bits(pgprot_t prot);
#define arch_calc_vmalloc_prot_bits arm64_calc_vmalloc_prot_bits

#endif /* _ASM_ARM64_VMALLOC_H */
