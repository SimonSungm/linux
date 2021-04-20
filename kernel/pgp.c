#include <linux/pgp.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/mm.h>

bool pgp_ro_buf_ready =false;
spinlock_t ro_pgp_pages_lock=__SPIN_LOCK_UNLOCKED();
static char ro_pages_stat[PGP_RO_PAGES]={0};
unsigned int ro_alloc_avail=0;

/* 
 * whether a given addr is ro_page or not
 * @ret: false if not a ro page, true if a ro page
 */
bool is_pgp_ro_page(u64 addr)
{
    if((addr>=(u64)PGP_ROBUF_VA)&&(addr<(u64)(PGP_ROBUF_VA+PGP_ROBUF_SIZE)))
        return true;
    return false;
}
/* 
 * find a free page for alloc
 * @ret: vaddr of page     or   NULL if fail
 */

void *pgp_ro_alloc(void)
{
    unsigned long flags;
    unsigned int i=0;
    void *alloc_addr=NULL;
    bool found=false;

    if(!pgp_ro_buf_ready)
        return alloc_addr;
    spin_lock_irqsave(&ro_pgp_pages_lock,flags);
    while(i<PGP_RO_PAGES)
    {
        if(!ro_pages_stat[ro_alloc_avail])
        {
            found=true;
            if(i==PGP_RO_PAGES-1)
            {
                PR_ERR("Ro buf slot is last one\n");
            }
            break;
        }
        ro_alloc_avail=(ro_alloc_avail+1)%PGP_RO_PAGES;
        i++;
    }

    if(found)
    {
        alloc_addr=(void *)((u64)(PGP_ROBUF_VA)+(ro_alloc_avail<<PAGE_SHIFT));
        ro_pages_stat[ro_alloc_avail]=true;
        ro_alloc_avail=(ro_alloc_avail+1)%PGP_RO_PAGES;
    }
    spin_unlock_irqrestore(&ro_pgp_pages_lock,flags);
    return alloc_addr;

}

/* 
 * free a page with vaddr is free_addr
 * @ret: false if not a ro page to free, true if a ro page to free
 *
 *
 */

bool pgp_ro_free(void *free_addr)
{
    unsigned int i;
    unsigned long flags;
    if(!is_pgp_ro_page((u64)free_addr))
        return false;
    i=((u64)free_addr-(u64)PGP_ROBUF_VA)>>PAGE_SHIFT;
    spin_lock_irqsave(&ro_pgp_pages_lock,flags);
    ro_pages_stat[i]=false;
    ro_alloc_avail=i;
    spin_unlock_irqrestore(&ro_pgp_pages_lock,flags);
    return true;
}

/* 
 * 
 * for ro page use hypercall and for normal page use normal memcpy
 *
 *
 */
void pgp_memcpy(void *dst,const void *src,size_t len)
{
    if(is_pgp_ro_page((u64)dst))
    {

    }
    else
    {
        memcpy(dst,src,len);
    }
}