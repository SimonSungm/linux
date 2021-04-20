// SPDX-License-Identifier: GPL-2.0-only
/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

static struct kmem_cache *pgd_cache __ro_after_init;

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	gfp_t gfp = GFP_PGTABLE_USER;
#ifdef CONFIG_PAGE_TABLE_PROTECTION_PGD
	pgd_t* pgd;
	pgd=(pgd_t *)pgp_ro_alloc();
	if(!pgd)
	{
		printk("[PGP]: pgd allocation fail, use normal alloctor instead\n");
		if (PGD_SIZE == PAGE_SIZE)
			return (pgd_t *)__get_free_page(gfp);
		else
			return kmem_cache_alloc(pgd_cache, gfp);
	}
	return pgd;

#else
	if (PGD_SIZE == PAGE_SIZE)
		return (pgd_t *)__get_free_page(gfp);
	else
		return kmem_cache_alloc(pgd_cache, gfp);
#endif
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{

#ifdef CONFIG_PAGE_TABLE_PROTECTION_PGD
	if(pgp_ro_free(void* pgd))
	{
		printk("[PGP]: pgd free fail, not a pgp page\n");
		if (PGD_SIZE == PAGE_SIZE)
			free_page((unsigned long)pgd);
		else
			kmem_cache_free(pgd_cache, pgd);
	}
#else
	if (PGD_SIZE == PAGE_SIZE)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
#endif
}

void __init pgtable_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

#ifdef CONFIG_ARM64_PA_BITS_52
	/*
	 * With 52-bit physical addresses, the architecture requires the
	 * top-level table to be aligned to at least 64 bytes.
	 */
	BUILD_BUG_ON(PGD_SIZE < 64);
#endif

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}
