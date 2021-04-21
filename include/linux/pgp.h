#ifndef _PGP_H
#define _PGP_H

#include <linux/types.h>
#include <asm/bug.h>
#include <asm/io.h>
#include <linux/pt.h>

extern bool pgp_hyp_init;

#define __DEBUG_PAGE_TABLE_PROTECTION
/* defined in init/main.c */
#define PGP_RO_BUF_BASE 0x10000000

#define PGP_ROBUF_SIZE (0x10000000)
#define PGP_RO_PAGES (PGP_ROBUF_SIZE >> PAGE_SHIFT)
#define PGP_ROBUF_VA (phys_to_virt(PGP_RO_BUF_BASE))

#ifdef __DEBUG_PAGE_TABLE_PROTECTION
#define PGP_WARNING(format...) printk(format)
//#define PGP_WARNING(format...) WARN(true, format)
#define PGP_WRITE_ONCE(addr, value) WRITE_ONCE(*(unsigned long *)addr, (unsigned long)value)
#else
#define PGP_WARNING(format...) 
#define PGP_WRITE_ONCE(addr, value) pgp_write_long(addr, (unsigned long)value);
#endif

/* defined in kernel/pgp.c */
void *pgp_ro_alloc(void);
void *pgp_ro_zalloc(void);
bool pgp_ro_free(void* addr);
void pgp_memcpy(void *dst, const void *src, size_t len);
void pgp_memset(void *dst, char n, size_t len);

static inline bool is_pgp_ro_page(u64 addr)
{
#ifndef __DEBUG_PAGE_TABLE_PROTECTION
	if(pgp_hyp_init == false)
		return false;
#endif

	if ((addr >= (u64)PGP_ROBUF_VA)
		&& (addr < (u64)(PGP_ROBUF_VA + PGP_ROBUF_SIZE)))
		return true;
	else
		return false;
}

static inline void pgp_write_long(void *addr, unsigned long val)
{
	unsigned long phys = (unsigned long)(virt_to_phys(addr));

	jailhouse_call_arg2_custom(JAILHOUSE_HC_WRITE_LONG, phys, val);
}

#endif // _PGP_H
