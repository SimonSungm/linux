#ifndef _PGP_H
#define _PGP_H
/* defined in init/main.c */
extern u64 robuf_start_pgp;
extern u8 pgp_started;
extern bool pgp_ro_buf_ready;

#define PGP_ROBUF_START ({ robuf_start_pgp; })
#define PGP_ROBUF_SIZE (0x400000)
#define PGP_RO_PAGES (PGP_ROBUF_SIZE >> PAGE_SHIFT)
#define PGP_ROBUF_VA (phys_to_virt(PGP_ROBUF_START))
// #ifdef CONFIG_PAGE_TABLE_PROTECTION
// #elif defined(CONFIG_PMP_PGP_PMD)
// #else
// #define PGP_ROBUF_SIZE (0x1000000)
// #endif

#define PGP_WRITE_ONCE()

/* defined in kernel/pgp.c */
void *pgp_ro_alloc(void);
bool pgp_ro_free(void* addr);
bool is_pgp_ro_page(u64 addr);
void pgp_memcpy(void *dst, const void *src, size_t len);

#endif // _PGP_H
