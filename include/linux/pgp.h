#ifndef _PGP_H
#define _PGP_H

#include <linux/types.h>
#include <asm/bug.h>
#include <asm/io.h>
#include <linux/pt.h>

extern volatile bool pgp_hyp_init;
extern unsigned long pgp_ro_buf_base;
extern unsigned long pgp_ro_buf_base_va;
extern bool pgp_ro_buf_ready;

//#define __DEBUG_PAGE_TABLE_PROTECTION
#define PGP_DEBUG_ALLOCATION
/* defined in init/main.c */
#define PGP_RO_BUF_BASE pgp_ro_buf_base
#define PGP_ROBUF_VA pgp_ro_buf_base_va

#define PGP_ROBUF_SIZE (0x8000000UL)
#define PGP_RO_PAGES (PGP_ROBUF_SIZE >> PAGE_SHIFT)

#ifdef __DEBUG_PAGE_TABLE_PROTECTION
#define PGP_WARNING_SET(format...) 
#define PGP_WARNING(format...) printk(format)
//#define PGP_WARNING(format...) WARN(true, format)
#define PGP_WRITE_ONCE(addr, value) WRITE_ONCE(*(unsigned long *)addr, (unsigned long)value)
#else
#define PGP_WARNING_SET(format...) 
#define PGP_WARNING(format...)
#define PGP_WRITE_ONCE(addr, value) pgp_write_long((unsigned long *)addr, (unsigned long)value);
#endif

/* defined in kernel/pgp.c */
void *pgp_ro_alloc(void);
void *pgp_ro_zalloc(void);
bool pgp_ro_free(void* addr);
void pgp_memcpy(void *dst, void *src, size_t len);
void pgp_memset(void *dst, char n, size_t len);

static inline bool is_pgp_ro_page(unsigned long addr)
{
	if ((addr >= (unsigned long)PGP_ROBUF_VA)
		&& (addr < (unsigned long)(PGP_ROBUF_VA + PGP_ROBUF_SIZE)))
		return true;
	else
		return false;
}

static inline void pgp_write_long(unsigned long *addr, unsigned long val)
{
	if(pgp_hyp_init == false)
		WRITE_ONCE(*addr, val);
	else
		jailhouse_call_arg2_custom(JAILHOUSE_HC_WRITE_LONG, (unsigned long)addr, val);
}

#endif // _PGP_H
