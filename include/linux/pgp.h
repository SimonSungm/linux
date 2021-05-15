#ifndef _PGP_H
#define _PGP_H

#include <linux/types.h>
#include <asm/bug.h>
#include <asm/io.h>
#include <linux/pt.h>

extern volatile bool pgp_hyp_init;
extern unsigned long pgp_ro_buf_base;
extern unsigned long pgp_ro_buf_end;
extern unsigned long pgp_ro_buf_base_va;
extern unsigned long pgp_ro_buf_end_va;
extern bool pgp_ro_buf_ready;

//#define __DEBUG_PAGE_TABLE_PROTECTION
#define PGP_DEBUG_ALLOCATION
/* defined in kernel/pgp.c */
#define PGP_RO_BUF_BASE pgp_ro_buf_base
#define PGP_ROBUF_VA pgp_ro_buf_base_va

#define PGP_ROBUF_SIZE (0x8000000UL)
#define PGP_RO_PAGES (PGP_ROBUF_SIZE >> PAGE_SHIFT)

#ifdef __DEBUG_PAGE_TABLE_PROTECTION
#define PGP_WARNING_SET(format...) 
#define PGP_WARNING(format...) WARN(true, format)
#define PGP_WRITE_ONCE(addr, value) WRITE_ONCE(*(unsigned long *)addr, (unsigned long)value)
#else
#define PGP_WARNING_SET(format...) 
#define PGP_WARNING(format...)
#define PGP_WRITE_ONCE(addr, value) pgp_write_long((unsigned long *)addr, (unsigned long)value);
#endif


/**
 * Initialize a page list which links all pages in pgp ro buffer.
 */
void __init init_pgp_page_list(void);

/**
 * pgp_ro_alloc - alloc a page from pgp ro buffer
 * @return: struct page of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
struct page *pgp_ro_alloc(void);

/**
 * pgp_ro_zalloc - alloc a page from pgp ro buffer and set the page memory to 0.
 * @return: base vitural address of the allocated page on success, NULL on failure
 *
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 */
void *pgp_ro_zalloc(void);

/* 
 * pgp_ro_free - free a page to pgp ro buffer.
 * @ret: false if not a ro page to free, true if a ro page to free
 * 
 * Spin lock is userd and IRQ is disabled when we alloc the page.
 * In case of a ro page free, it should never fail.
 */
bool pgp_ro_free(void* addr);

/* 
 * pgp_memset - initialize the memory region.
 * @dst: base virtual address of the memroy region.
 * @c: the value of the byte that all memory will be initialized to.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memset.
 */
void pgp_memset(void *dst, char n, size_t len);

/* 
 * pgp_memcpy - copy the content of the source memory region to the destination memory region.
 * @dst: base virtual address of the source memroy region.
 * @src: base virtual address of the destination memroy region.
 * @len: the length of the memory region in byte.
 * 
 * For a ro page use the jailhouse hypercall while for a normal page use the memcpy.
 */
void pgp_memcpy(void *dst, void *src, size_t len);

/* 
 * is_pgp_ro_page - determine whether a address is in a page from pgp ro buffer.
 * @addr: virtual address of the page.
 * @return: true if the address is in a page from pgp ro buffer.
 */
static inline bool is_pgp_ro_page(unsigned long addr)
{
	if (addr >= pgp_ro_buf_base_va && addr < pgp_ro_buf_end_va)
		return true;
	else
		return false;
}

/* 
 * pgp_write_long - write the long word to memory.
 * @addr: virtual address of the .
 * @val: value to be written.
 * 
 * For a addr from pgp ro region use the jailhouse hypercall use WRITE_ONCE otherwise.
 */
static inline void pgp_write_long(unsigned long *addr, unsigned long val)
{
	if(pgp_hyp_init == false)
		WRITE_ONCE(*addr, val);
	else
		jailhouse_call_arg2_custom(JAILHOUSE_HC_WRITE_LONG, (unsigned long)addr, val);
}

#endif // _PGP_H
