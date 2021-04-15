#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>	/* for copy_*_user */
#include <linux/sched/signal.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm-generic/sections.h>
#include <asm/sections.h>
#include <asm/io.h>
#include <linux/list.h>

#include "pt.h"

#define MAX_SIZE 4096

//#define __DEBUG_TEXT_PROTECTION

static char msg[MAX_SIZE];
extern char _stext[], _etext[];

#ifdef CONFIG_X86_64
//bool jailhouse_use_vmcall = true;

#define REGION_NUM 1
struct px_memory_region machine_mem[REGION_NUM] = {
    {
        .start = 0,
        .end = 0
    }
};

unsigned long phys_start = 0;
unsigned long phys_end = 0x4080000000;

// int module_walk_pud_entry(pud_t *pud, unsigned long addr,
// 			 unsigned long next, struct mm_walk *walk)
// {
//      pt_add_mem_region_size(addr & PUD_MASK, PUD_SIZE, "pud");
// }
// int module_walk_pmd_entry(pmd_t *pmd, unsigned long addr,
// 			 unsigned long next, struct mm_walk *walk)
// {
//      pt_add_mem_region_size(addr & PMD_MASK, PMD_SIZE, "pmd");
// }
// int module_walk_pud_entry(pte_t *pte, unsigned long addr,
// 			 unsigned long next, struct mm_walk *walk)
// {
//      pt_add_mem_region_size(addr & PTE_MASK, PTE_SIZE, "pte");
// }

// struct mm_walk_ops module_mm_walk_ops = {
// 	int (*pud_entry)(pud_t *pud, unsigned long addr,
// 			 unsigned long next, struct mm_walk *walk);
// 	int (*pmd_entry)(pmd_t *pmd, unsigned long addr,
// 			 unsigned long next, struct mm_walk *walk);
// 	int (*pte_entry)(pte_t *pte, unsigned long addr,
// 			 unsigned long next, struct mm_walk *walk);
// 	int (*pte_hole)(unsigned long addr, unsigned long next,
// 			struct mm_walk *walk);
// 	int (*hugetlb_entry)(pte_t *pte, unsigned long hmask,
// 			     unsigned long addr, unsigned long next,
// 			     struct mm_walk *walk);
// 	int (*test_walk)(unsigned long addr, unsigned long next,
// 			struct mm_walk *walk);
// };

#endif

LIST_HEAD(pt_mem_regions);


// int translate_mem(unsigned long start, unsigned long size)
// {
//     unsigned long va;
//     unsigned long end = start + size;
//     walk_page_range(&init_mm, start, end, )
// }

int pt_add_mem_region_size(unsigned long start, unsigned long size, char *name)
{
    return pt_add_mem_region(start, start+size, name);
}
EXPORT_SYMBOL(pt_add_mem_region_size);

// int pt_add_mem_region_merge(unsigned long start, unsigned long end, char *name)
// {
//     struct px_memory_region *new = kmalloc(sizeof(struct px_memory_region), GFP_KERNEL);
//     struct px_memory_region *ptr;
//     struct list_head *l;
//     new->start = start & PAGE_MASK;
//     new->end = PAGE_ALIGN(end);
//     new->name = name;
//     INIT_LIST_HEAD(&new->list);

//     list_for_each(l, &pt_mem_regions) {
//         ptr = list_entry(l, struct px_memory_region, list);
//         if(ptr->start >= new->start){
//             if(new->end >= ptr->start) {
//                 ptr->start = new->start;
//                 ptr->end = max(ptr->end, new->end);
//             }
//             else 
//                 list_add_tail(&new->list, l);
//             return 0;
//         } else if(ptr->end >= new->start) {
//             ptr->end = max(ptr->end, new->end);
//             return 0;
//         }
//     }
//     list_add_tail(&new->list, &pt_mem_regions);
//     return 0;
// }

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