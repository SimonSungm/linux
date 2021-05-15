#include <linux/pgp.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/mm.h>

unsigned long pgp_ro_buf_base = 0;
EXPORT_SYMBOL(pgp_ro_buf_base);
unsigned long pgp_ro_buf_end = 0;
EXPORT_SYMBOL(pgp_ro_buf_end);
unsigned long pgp_ro_buf_base_va = 0;
EXPORT_SYMBOL(pgp_ro_buf_base_va);
unsigned long pgp_ro_buf_end_va = 0;
EXPORT_SYMBOL(pgp_ro_buf_end_va);

bool pgp_ro_buf_ready = false;
EXPORT_SYMBOL(pgp_ro_buf_ready);
volatile bool pgp_hyp_init = false;
EXPORT_SYMBOL(pgp_hyp_init);

spinlock_t ro_pgp_pages_lock = __SPIN_LOCK_UNLOCKED();
LIST_HEAD(pgp_page_list);

/**
 * Initialize a page list which links all pages in pgp ro buffer.
 */
void __init init_pgp_page_list(void)
{
	unsigned long start_pfn = PFN_DOWN(pgp_ro_buf_base);
	unsigned long end_pfn = PFN_UP(pgp_ro_buf_end);
	
	for (; start_pfn < end_pfn; start_pfn++) {
		if (pfn_valid(start_pfn)) {
			struct page *page = pfn_to_page(start_pfn);
			list_add(&page->lru, &pgp_page_list);
		}
	}
}

/**
 * pgp_ro_alloc - alloc a page from pgp ro buffer
 * @return: struct page of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
struct page *pgp_ro_alloc(void)
{
	unsigned long flags;
	struct page *page = NULL;
	static int i = 0;

	if(!pgp_ro_buf_ready)
		goto out;
	
	spin_lock_irqsave(&ro_pgp_pages_lock, flags);
	page = list_first_entry_or_null(&pgp_page_list, struct page, lru);
	if(page != NULL) {
		list_del(&page->lru);
	}
	spin_unlock_irqrestore(&ro_pgp_pages_lock,flags);

out:
	return page;
}
EXPORT_SYMBOL(pgp_ro_alloc);

/**
 * pgp_ro_zalloc - alloc a page from pgp ro buffer and set the page memory to 0.
 * @return: base vitural address of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
void *pgp_ro_zalloc(void)
{
	struct page *page;
	void *ret = NULL;
	
	page = pgp_ro_alloc();
	if(page != NULL) {
		ret = page_address(page);
		pgp_memset(ret, 0, PAGE_SIZE);
	}
	return ret;
}
EXPORT_SYMBOL(pgp_ro_zalloc);

/* 
 * pgp_ro_free - free a page to pgp ro buffer.
 * @ret: false if not a ro page to free, true if a ro page to free
 * 
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 * In case of a ro page free, it should never fail.
 */
bool pgp_ro_free(void* addr)
{
	unsigned long flags;
	struct page *page = virt_to_page(addr);

	if(!is_pgp_ro_page((unsigned long)addr))
        return false;
	
	spin_lock_irqsave(&ro_pgp_pages_lock, flags);
	list_add(&page->lru, &pgp_page_list);
	spin_unlock_irqrestore(&ro_pgp_pages_lock, flags);

	return true;
}
EXPORT_SYMBOL(pgp_ro_free);

/* 
 * pgp_memset - initialize the memory region.
 * @dst: base virtual address of the memroy region.
 * @c: the value of the byte that all memory will be initialized to.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memset.
 */
void pgp_memset(void *dst, char c, size_t len)
{
	if(is_pgp_ro_page((unsigned long)dst)){
#ifdef __DEBUG_PAGE_TABLE_PROTECTION
		memset(dst, c, len);
#else
		if(pgp_hyp_init == false)
			memset(dst, c, len);
		else
			jailhouse_call_arg2_custom(JAILHOUSE_HC_MEMSET | len, (unsigned long)dst, c);
#endif
    } else {
#ifndef __DEBUG_PAGE_TABLE_PROTECTION
		if(pgp_hyp_init && pgp_ro_buf_ready)
			printk("[PGP] pgp_memset fail at 0x%016lx", (unsigned long)dst);
#endif
        memset(dst, c, len);
    }
}
EXPORT_SYMBOL(pgp_memset);

/* 
 * pgp_memcpy - copy the content of the source memory region to the destination memory region.
 * @dst: base virtual address of the source memroy region.
 * @src: base virtual address of the destination memroy region.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memcpy.
 */
void pgp_memcpy(void *dst, void *src, size_t len)
{
    if(is_pgp_ro_page((unsigned long)dst)){
#ifdef __DEBUG_PAGE_TABLE_PROTECTION
		memcpy(dst, src, len);
#else
		if(pgp_hyp_init == false)
			memcpy(dst, src, len);
		else
			jailhouse_call_arg2_custom(JAILHOUSE_HC_MEMCPY | len, (unsigned long)dst, (unsigned long)virt_to_phys(src));
#endif
    } else {
#ifndef __DEBUG_PAGE_TABLE_PROTECTION
		if(pgp_hyp_init && pgp_ro_buf_ready)
			printk("[PGP] pgp_memcpy fail from src 0x%016lx to dst 0x%016lx", (unsigned long)src, (unsigned long)dst);
#endif
        memcpy(dst, src, len);
    }
}
EXPORT_SYMBOL(pgp_memcpy);