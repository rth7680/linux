// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/kmemleak.h>
#include <linux/linkage.h>
#include <linux/memblock.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>
#include <linux/bug.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "kasan.h"
#include "../slab.h"

bool kasan_hw_tags_enabled()
{
	return is_hw_tags_enabled();
}
EXPORT_SYMBOL_GPL(kasan_hw_tags_enabled);

/*
 * Stores tag in memory for the memory range [addr, addr + size)
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 * When ignore_tag is true, the tag is derived by address and the
 * tag parameter is ignored.
 * Requires HW enabled tagging feature.
 */
void * __must_check kasan_set_mem_tag(const void *address, size_t size,
				      u8 tag, bool ignore_tag)
{
	void *curr_addr = set_mem_tag((void *)address, size, tag, ignore_tag);

	return curr_addr;
}

#define kasan_init_mem_tag(address, size) \
			kasan_set_mem_tag(address, size, 0, true)
#define kasan_update_mem_tag(address, size, tag) \
			kasan_set_mem_tag(address, size, tag, false)

void kasan_unpoison_shadow(const void *address, size_t size) {
	/* Make accessible the whole area [address, address +size) */
	address = kasan_init_mem_tag(address, size);
}

void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
			slab_flags_t *flags)
{
	*flags |= SLAB_KASAN;
}

void kasan_poison_slab(struct page *page)
{
	void *__page;
	unsigned long i;

	for (i = 0; i < compound_nr(page); i++)
		page_kasan_tag_reset(page + i);

	__page = kasan_update_mem_tag(page_address(page),
				      page_size(page),
				      KASAN_KMALLOC_REDZONE);

	(void)__page;
}

void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
{
	object = kasan_init_mem_tag(object, cache->object_size);
}

void kasan_poison_object_data(struct kmem_cache *cache, void *object)
{
	object = kasan_update_mem_tag(object,
			round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE),
			KASAN_KMALLOC_REDZONE);
}

void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
						const void *object)
{
	if (!(cache->flags & SLAB_KASAN))
		return (void *)object;

	object = set_tag(object,
			 assign_tag(cache, object, true, false));

	return (void *)object;
}


static bool __kasan_slab_free(struct kmem_cache *cache,
			      void *object, unsigned long ip)
{
	unsigned long rounded_up_size;

	/* RCU slabs could be legally used after free within the RCU period */
	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
		return false;

	rounded_up_size = round_up(cache->object_size, KASAN_SHADOW_SCALE_SIZE);
	object = kasan_update_mem_tag(object, rounded_up_size,
				      KASAN_KMALLOC_FREE);

	return true;
}

bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
{
	return __kasan_slab_free(cache, object, ip);
}

static void * __kasan_kmalloc(struct kmem_cache *cache, const void *object,
			      size_t size, gfp_t flags, bool keep_tag)
{
	void *redzone_start;
	void *redzone_end;
	size_t redzone_size;
	void *curr_obj = (void *)object;
	u8 tag = assign_tag(cache, object, false, keep_tag);

	if (unlikely(object == NULL))
		return NULL;

	redzone_start = (void *)round_up((unsigned long)(object + size),
					 KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (void *)round_up((unsigned long)object + cache->object_size,
				       KASAN_SHADOW_SCALE_SIZE);
	redzone_size = ((size_t)((unsigned long)redzone_end -
				(unsigned long)redzone_start));

	curr_obj = kasan_update_mem_tag(object, size, tag);
	redzone_start = kasan_update_mem_tag(redzone_start, redzone_size,
					     KASAN_KMALLOC_REDZONE);

	return curr_obj;
}

void * __must_check kasan_slab_alloc(struct kmem_cache *cache, void *object,
				     gfp_t flags)
{
	return __kasan_kmalloc(cache, object, cache->object_size, flags, false);
}

void * __must_check kasan_kmalloc(struct kmem_cache *cache, const void *object,
				  size_t size, gfp_t flags)
{
	return __kasan_kmalloc(cache, object, size, flags, true);
}
EXPORT_SYMBOL(kasan_kmalloc);

void * __must_check kasan_kmalloc_large(const void *ptr, size_t size,
					gfp_t flags)
{
	void *redzone_start;
	void *redzone_end;
	size_t redzone_size;
	struct page *page;
	void *curr_ptr = (void *)ptr;

	if (unlikely(ptr == NULL))
		return NULL;

	page = virt_to_page(ptr);
	redzone_start = (void *)round_up((unsigned long)(ptr + size),
					 KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (void *)((unsigned long)ptr + page_size(page));
	redzone_size = ((size_t)((unsigned long)redzone_end -
				(unsigned long)redzone_start));

	curr_ptr = kasan_init_mem_tag(ptr, size);
	redzone_start = kasan_update_mem_tag(redzone_start, redzone_size,
					     KASAN_PAGE_REDZONE);

	return curr_ptr;
}

void * __must_check kasan_krealloc(const void *object, size_t size, gfp_t flags)
{
	struct page *page;

	if (unlikely(object == ZERO_SIZE_PTR))
		return (void *)object;

	page = virt_to_head_page(object);

	if (unlikely(!PageSlab(page)))
		return kasan_kmalloc_large(object, size, flags);
	else
		return __kasan_kmalloc(page->slab_cache, object, size,
				       flags, true);
}

void kasan_poison_kfree(void *ptr, unsigned long ip)
{
	struct page *page = virt_to_head_page(ptr);

	if (unlikely(!PageSlab(page)))
		ptr = kasan_update_mem_tag(ptr, page_size(page),
					   KASAN_FREE_PAGE);
	else
		__kasan_slab_free(page->slab_cache, ptr, ip);
}

void kasan_kfree_large(void *ptr, unsigned long ip)
{
	kasan_poison_kfree(ptr, ip);
}

void kasan_unpoison_slab(const void * ptr)
{
	ptr = kasan_init_mem_tag(ptr, __ksize(ptr));
}

void kasan_alloc_pages(struct page *page, unsigned int order)
{
	void *__page;
	unsigned long i;
	u8 tag = random_tag();

	if (unlikely(PageHighMem(page)))
		return;

	for (i = 0; i < (1 << order); i++)
		page_kasan_tag_set(page + i, tag);

	__page = kasan_update_mem_tag(page_address(page),
				      PAGE_SIZE << order,
				      tag);

	(void)__page;
}

void kasan_free_pages(struct page *page, unsigned int order)
{
	void *__page;

	if (likely(!PageHighMem(page)))
		__page = kasan_update_mem_tag(page_address(page),
					      PAGE_SIZE << order,
					      KASAN_FREE_PAGE);

	(void)__page;
}
