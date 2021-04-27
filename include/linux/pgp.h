#ifndef _PGP_H
#define _PGP_H

#include <linux/types.h>
#include <linux/pt.h>
#include <asm/memory.h>

extern volatile bool pgp_hyp_init;
extern unsigned long pgp_ro_buf_base;
extern bool pgp_ro_buf_ready;
/* defined in init/main.c */
#ifdef CONFIG_X86_64
#define PGP_RO_BUF_BASE 0x10000000
#endif

#ifdef CONFIG_ARM64
#define PGP_RO_BUF_BASE (0x50000000)
#endif

//#define __DEBUG_PAGE_TABLE_PROTECTION

#define PGP_ROBUF_SIZE (0x8000000)
#define PGP_RO_PAGES (PGP_ROBUF_SIZE >> PAGE_SHIFT)
#define PGP_ROBUF_VA (__va(PGP_RO_BUF_BASE))

#ifdef __DEBUG_PAGE_TABLE_PROTECTION
#define PGP_WARNING(format...) printk(format)
//#define PGP_WARNING(format...) WARN(true, format)
#define PGP_WRITE_ONCE(addr, value) WRITE_ONCE(*(unsigned long *)addr, (unsigned long)value)
#else
#define PGP_WARNING_SET(format...) 
#define PGP_WARNING(format...) WARN(true, format)
#define PGP_WRITE_ONCE(addr, value) pgp_write_long((unsigned long *)addr, (unsigned long)value);
#endif


/* defined in kernel/pgp.c */
void *pgp_ro_alloc(void);
void *pgp_ro_zalloc(void);
bool pgp_ro_free(void* addr);
void pgp_memcpy(void *dst, const void *src, size_t len);
void pgp_memset(void *dst, char n, size_t len);

static inline bool is_pgp_ro_page(u64 addr)
{
// #ifndef __DEBUG_PAGE_TABLE_PROTECTION
// 	if(pgp_hyp_init == false)
// 		return false;
// #endif
//    printk("########[PGP]addr= 0x%016llx,PGP_ROBUF_VA= 0x%016llx,PGP_ROBUF_VA + PGP_ROBUF_SIZE= 0x%016llx#######\n",(u64)addr,(u64)PGP_ROBUF_VA,(u64)(PGP_ROBUF_VA + PGP_ROBUF_SIZE));
	if ((addr >= (u64)PGP_ROBUF_VA)
		&& (addr < (u64)(PGP_ROBUF_VA + PGP_ROBUF_SIZE)))
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
