#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>	/* for copy_*_user */
#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched/task.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/efi.h>
#include <linux/set_memory.h>

#include <asm-generic/sections.h>
#include <asm/sections.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

#include <linux/pt.h>
#include <linux/pgp.h>

#define MAX_SIZE 4096

#ifndef CONFIG_X86
#define __DEBUG_TEXT_PROTECTION
#endif

static char msg[MAX_SIZE];
extern char _stext[], _etext[];

#define REGION_NUM 1
struct px_memory_region machine_mem[REGION_NUM] = {
    {
        .start = 0,
        .end = 0
    }
};

unsigned long phys_start = 0;
unsigned long phys_end = 0x4080000000;

LIST_HEAD(pt_mem_regions);
#ifdef CONFIG_X86
#define pgd_leaf pgd_large
#define p4d_leaf p4d_large
#define pud_leaf pud_large
#define pmd_leaf pmd_large

#if CONFIG_PGTABLE_LEVELS > 4
#define pgdp_page_vaddr(pgdp) pgd_page_vaddr(*pgdp)
#else
#define pgdp_page_vaddr(pgdp) (pgdp)
#endif
#define p4dp_page_vaddr(p4dp) p4d_page_vaddr(*p4dp)
#define pudp_page_vaddr(pudp) pud_page_vaddr(*pudp)
#define pmdp_page_vaddr(pmdp) pmd_page_vaddr(*pmdp)
#endif
#ifdef CONFIG_ARM64
static inline bool pgd_leaf(pgd_t pgd) { return false; }
static inline bool p4d_leaf(p4d_t p4d) { return false; }
#define p4d_present(p4d) (p4d_val(p4d))
#define pud_leaf pud_sect
#define pmd_leaf pmd_sect

#define pgdp_page_vaddr(pgdp) (pgdp)
#if CONFIG_PGTABLE_LEVELS > 3
#define p4dp_page_vaddr(pgdp) __va(pgd_page_paddr(*pgdp))
#else
#define p4dp_page_vaddr(pgdp) (p4dp)
#endif
#define pudp_page_vaddr(pudp) __va(pud_page_paddr(*pudp))
#define pmdp_page_vaddr(pmdp) __va(pmd_page_paddr(*pmdp))
#endif

struct pgp_fail_struct {
    unsigned long addr;
    char *name;
    struct list_head list;
};
LIST_HEAD(pgp_fail_list);

int pgp_check_fail(unsigned long addr, char *name)
{
    struct pgp_fail_struct *p, *new;
    list_for_each_entry(p, &pgp_fail_list, list) {
        if(addr == p->addr)
            return 0;
        else if(addr < p->addr) {
            new = kmalloc(sizeof(struct pgp_fail_struct), GFP_KERNEL);
            new->addr = addr;
            new->name = name;
            if(!new)
                panic("cannot alloc pgp fail struct\n");
            list_add_tail(&(new->list), &(p->list));
            return 0;
        }
    }
    new = kmalloc(sizeof(struct pgp_fail_struct), GFP_KERNEL);
    new->addr = addr;
    new->name = name;
    if(!new)
        panic("cannot alloc pgp fail struct\n");
    list_add_tail(&(new->list), &pgp_fail_list);
    return 0;
}

int check_pte(pte_t *ptep)
{
    if(!is_pgp_ro_page((unsigned long)ptep))
        pgp_check_fail((unsigned long)ptep, "pte");

    return 0;   
}

int check_pmd(pmd_t *pmdp)
{
    int i;
    if(!is_pgp_ro_page((unsigned long)pmdp))
        pgp_check_fail((unsigned long)pmdp, "pmd");
    
    for (i = 0; i < PTRS_PER_PMD; i++) {
        if(pmd_present(*pmdp) && !pmd_leaf(*pmdp)){
            check_pte((pte_t *)pmdp_page_vaddr(pmdp));
        }
        pmdp++;
    }
    return 0;
}

int check_pud(pud_t *pudp)
{
    int i;
    if(!is_pgp_ro_page((unsigned long)pudp))
        pgp_check_fail((unsigned long)pudp, "pud");

    for (i = 0; i < PTRS_PER_PUD; i++) {
        if(pud_present(*pudp) && !pud_leaf(*pudp)){
            check_pmd((pmd_t *)pudp_page_vaddr(pudp));
        }
        pudp++;
    }
    return 0;
}

int check_p4d(p4d_t *p4dp)
{
    int i;
    if(!is_pgp_ro_page((unsigned long)p4dp))
        pgp_check_fail((unsigned long)p4dp, "p4d");

    for (i = 0; i < PTRS_PER_P4D; i++) {
        if(p4d_present(*p4dp) && !p4d_leaf(*p4dp)){
            check_pud((pud_t *)p4dp_page_vaddr(p4dp));
        }
        p4dp++;
    }
    return 0;
}

int check_pgd(pgd_t *pgdp)
{
    int i;
    if(!is_pgp_ro_page((unsigned long)pgdp))
        pgp_check_fail((unsigned long)pgdp, "pgd");

    for (i = 0; i < PTRS_PER_PGD; i++) {
        if(pgd_present(*pgdp) && !pgd_leaf(*pgdp)){
            check_p4d((p4d_t *)pgdp_page_vaddr(pgdp));
        }
        pgdp++;
    }
    return 0;
}

int check_pgt_region(void)
{
    struct task_struct *process, *task;
    struct mm_struct *mm;
    pgd_t *pgdp;
    struct pgp_fail_struct *p;
    int cnt = 0;

    for_each_process_thread(process, task) {
        get_task_struct(task);
        mm = task->mm;
        if(mm != NULL) {
            down_read(&mm->mmap_sem);
            pgdp = mm->pgd;
            if(pgdp)
                check_pgd(pgdp);
            up_read(&mm->mmap_sem);
        }
        mm = task->active_mm;
        if(mm != NULL){
            down_read(&mm->mmap_sem);
            pgdp = mm->pgd;
            if(pgdp)    
                check_pgd(pgdp); 
            up_read(&mm->mmap_sem);
        }
        put_task_struct(task);
    }
#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
    down_read(&efi_mm.mmap_sem);
    pgdp = efi_mm.pgd;
    if(pgdp)
        check_pgd(pgdp);
    up_read(&efi_mm.mmap_sem);
#endif
    list_for_each_entry(p, &pgp_fail_list, list) {
        printk("[PGP WARNING CHECK] addr: 0x%016lx, name: %s\n", p->addr, p->name);
        cnt ++;
    }
    printk("[PGP WARNING CHECK] total fail: %d\n", cnt);
    while(p = list_first_entry_or_null(&pgp_fail_list, struct pgp_fail_struct, list)) {
        list_del(&(p->list));
        kfree(p);
    }
    return 0;
}

int pt_add_mem_region_size(unsigned long start, unsigned long size, char *name)
{
    return pt_add_mem_region(start, start+size, name);
}
EXPORT_SYMBOL(pt_add_mem_region_size);

int pt_add_mem_region(unsigned long start, unsigned long end, char *name)
{
    struct px_memory_region *new = kmalloc(sizeof(struct px_memory_region), GFP_KERNEL);
    struct px_memory_region *ptr;
    struct list_head *l;

    if(start == end) return 0;

    new->start = start & PAGE_MASK;
    new->end = PAGE_ALIGN(end);
    new->name = name;
    INIT_LIST_HEAD(&new->list);

    list_for_each(l, &pt_mem_regions) {
        ptr = list_entry(l, struct px_memory_region, list);
        if(ptr->start > new->start){
            list_add_tail(&new->list, l);
            return 0;
        }
    }
    list_add_tail(&new->list, &pt_mem_regions);
    return 0;
}
EXPORT_SYMBOL(pt_add_mem_region);

int gphys2phys_pxn(void)
{
    struct px_memory_region *ptr;
    struct list_head *l;
    unsigned long last = phys_start;

    printk("======================= TEXT SECTION PROTECTION =========================\n");
    list_for_each(l, &pt_mem_regions) {
        ptr = list_entry(l, struct px_memory_region, list);
        if(ptr->start - last != 0) {
#ifndef __DEBUG_TEXT_PROTECTION
            jailhouse_call_arg2_custom(JAILHOUSE_HC_GPHYS2PHYS_PXN, last, ptr->start-last);
#else
            printk("[hypercall] last: 0x%016lx, size: 0x%016lx\n", last, ptr->start-last);
#endif 
        }
        last = ptr->end;
    }
    if(phys_end - last != 0) {
#ifndef __DEBUG_TEXT_PROTECTION
        jailhouse_call_arg2_custom(JAILHOUSE_HC_GPHYS2PHYS_PXN, last, phys_end-last);
#else
        printk("[hypercall] last: 0x%016lx, size: 0x%016lx\n", last, ptr->start-last);
#endif 
    }
    printk("======================= TEXT SECTION PROTECTION =========================\n");
    return 0;
}

ssize_t proc_read(struct file *filp, char __user *buf, size_t count, loff_t *offp) 
{
    struct px_memory_region *ptr;
    struct list_head *l;
    unsigned long last = 0;

    printk("============== module phys statics ==============\n");
    list_for_each(l, &pt_mem_regions) {
        ptr = list_entry(l, struct px_memory_region, list);
        printk("Module Name: %s, region: 0x%016lx---0x%016lx\n", ptr->name, ptr->start, ptr->end);
        if(last > ptr->start) printk("WARNING: THERE IS AN OVERLAP\n");
        last = ptr->end;
    }
    //check_pgt_region();
    printk("[PGP INIT] PAGE_TABLE_PROTECTION: start_pa is 0x%016lx, start_va is 0x%016lx, size is 0x%016lx\n", PGP_RO_BUF_BASE, PGP_ROBUF_VA, PGP_ROBUF_SIZE);
#ifdef PGP_DEBUG_ALLOCATION
    printk("[PGP]: Available pgp pages: %d, Alloc count: %ld, Free count: %ld, Used: %ld\n", pgcnt, alloc_cnt, free_cnt, alloc_cnt-free_cnt);
#endif
    if(*offp > 0) return 0;
	return 0;
}

ssize_t proc_write(struct file *filp,const char *buf,size_t count,loff_t *offp)
{
    int remain, id;

	if (count > MAX_SIZE){
		count =  MAX_SIZE;
	}

    remain = count;
    while(remain != 0){
        remain = copy_from_user(msg+count-remain, buf+count-remain, remain);
    }
    
    sscanf(msg, "%d", &id);
    switch(id) {
        case JAILHOUSE_HC_GPHYS2PHYS_PXN:
            if(gphys2phys_pxn() == 0) {
                printk("Successufully enable kernel text protection");
            }
            else {
                printk("Fail to enable kernel text protection");
            }
            break;
        case SET_MEM_RO:
            set_memory_ro(PGP_ROBUF_VA, PGP_RO_PAGES);
            printk("[PGP] set PGP buffer ro\n");
            break;
        case SET_MEM_RW:
            set_memory_rw(PGP_ROBUF_VA, PGP_RO_PAGES);
            printk("[PGP] set PGP buffer rw\n");
            break;
        default:
            break;
    }
    
	return count;
}

static const struct file_operations proc_ops = {
	/*.owner = THIS_MODULE,*/
	/*.open = pmp_module_open,*/
	.read = proc_read,
	.write = proc_write,
	/*.llseek = seq_lseek,*/
	/*.release = single_release,*/
};

static int __init pt_module_init(void) {
    int i;

    for(i = 0; i < REGION_NUM; ++ i){
        pt_add_mem_region(machine_mem[i].start, machine_mem[i].end, "no_name");
    }
    pt_add_mem_region(__pa(_stext), __pa(_etext), "kernel text");
    proc_create("pt_module", 0666, NULL, &proc_ops);
	return 0;
}

static void __exit pt_module_exit(void) {
    struct list_head *l;
    struct px_memory_region *ptr;

    while(!list_empty(&pt_mem_regions)){
        l = pt_mem_regions.next;
        ptr = list_entry(l, struct px_memory_region, list);
        list_del(l);
        kfree(ptr);
    }
	remove_proc_entry("pt_module", NULL);
}

MODULE_LICENSE("GPL");
module_init(pt_module_init);
module_exit(pt_module_exit);