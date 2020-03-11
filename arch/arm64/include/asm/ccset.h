/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_CCSET_H
#define __ASM_CCSET_H

/*
 * Macros to generate condition code outputs from inline assembly.
 * The output operand must be integral but type "bool" preferred.
 */
#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define CC_OUT(c) "=@cc" #c
# define CC_CLOBBER
#else
# define CC_SET(c) "\n\tcset %[_cc_" #c "], " #c "\n"
# define CC_OUT(c) [_cc_ ## c] "=r"
# define CC_CLOBBER "cc"
#endif

#endif /* __ASM_CCSET_H */
