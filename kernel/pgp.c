#include <linux/pgp.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/mm.h>

unsigned long pgp_ro_buf_base = 0;
EXPORT_SYMBOL(pgp_ro_buf_base);
bool pgp_ro_buf_ready = false;
EXPORT_SYMBOL(pgp_ro_buf_ready);
spinlock_t ro_pgp_pages_lock = __SPIN_LOCK_UNLOCKED();
static char ro_pages_stat[PGP_RO_PAGES] = {0};
unsigned int ro_alloc_avail = 0;
volatile bool pgp_hyp_init = false;
EXPORT_SYMBOL(pgp_hyp_init);


void *pgp_ro_alloc(void)
{
	unsigned long flags;
	unsigned int i = 0;
	void *alloc_addr = NULL;
	bool found = false;

	if(!pgp_ro_buf_ready)
		return alloc_addr;
	spin_lock_irqsave(&ro_pgp_pages_lock,flags);
	while(i < PGP_RO_PAGES) {
		if(ro_pages_stat[ro_alloc_avail] == false) {
			found = true;
			if(i == PGP_RO_PAGES - 1) {
				pr_err("Ro buf slot is last one\n");
			}
			break;
		}
		ro_alloc_avail = (ro_alloc_avail + 1) % PGP_RO_PAGES;
		i++;
	}
	if(found) {
		alloc_addr = (void *)((u64)(PGP_ROBUF_VA) + (ro_alloc_avail << PAGE_SHIFT));
		ro_pages_stat[ro_alloc_avail] = true;
		ro_alloc_avail = (ro_alloc_avail + 1) % PGP_RO_PAGES;
	}
	spin_unlock_irqrestore(&ro_pgp_pages_lock,flags);
    //	printk("##########[PGP]:success alloc ro page at addr=0x%016llx########\n",(u64)alloc_addr);
	return alloc_addr;
}
EXPORT_SYMBOL(pgp_ro_alloc);

void *pgp_ro_zalloc(void)
{
	void *alloc_addr = NULL;
	alloc_addr = pgp_ro_alloc();
	if(alloc_addr != NULL)
		pgp_memset(alloc_addr, 0, PAGE_SIZE);
	return alloc_addr;
}
EXPORT_SYMBOL(pgp_ro_zalloc);

/* 
 * 
 * @ret: false if not a ro page to free, true if a ro page to free
 *
 *
 */

bool pgp_ro_free(void* addr)
{
	unsigned int i;
	unsigned long flags;

	if(!is_pgp_ro_page((unsigned long)addr))
        return false;

	i =  ((u64)addr - (u64)PGP_ROBUF_VA) >> PAGE_SHIFT;
	spin_lock_irqsave(&ro_pgp_pages_lock, flags);
	ro_pages_stat[i] = false;
	ro_alloc_avail = i;
	spin_unlock_irqrestore(&ro_pgp_pages_lock, flags);
	//printk("##########[PGP]:success free ro page at addr=0x%016llx########\n",(u64)addr);
	return true;
}
EXPORT_SYMBOL(pgp_ro_free);

/* 
 * 
 * for ro page use hypercall and for normal page use normal memcpy
 *
 *
 */

void pgp_memset(void *dst, char n, size_t len)
{
	if(is_pgp_ro_page((unsigned long)dst)){
#ifdef __DEBUG_PAGE_TABLE_PROTECTION
		memset(dst, n, len);
#else
		if(pgp_hyp_init == false)
			memset(dst, n, len);
		else
			jailhouse_call_arg2_custom(JAILHOUSE_HC_MEMSET | len, (unsigned long)dst, n);
#endif
    } else {
#ifndef __DEBUG_PAGE_TABLE_PROTECTION
		printk("[PGP] pgp_memset fail at 0x%016lx", (unsigned long)dst);
#endif
        memset(dst, n, len);
    }
}
EXPORT_SYMBOL(pgp_memset);

void pgp_memcpy(void *dst, const void *src, size_t len)
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
		printk("[PGP] pgp_memcpy fail from src 0x%016lx to dst 0x%016lx", (unsigned long)src, (unsigned long)dst);
#endif
        memcpy(dst, src, len);
    }
}
EXPORT_SYMBOL(pgp_memcpy);