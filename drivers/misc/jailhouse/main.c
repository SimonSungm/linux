/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013-2017
 * Copyright (c) Valentine Sinitsyn, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

/* For compatibility with older kernel versions */
#include <linux/version.h>

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/firmware.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#endif
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/reboot.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <asm/barrier.h>
#include <asm/smp.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#ifdef CONFIG_ARM
#include <asm/virt.h>
#endif
#ifdef CONFIG_X86
#include <asm/msr.h>
#include <asm/apic.h>
#endif

#include "cell.h"
#include "jailhouse.h"
#include "main.h"
#include "pci.h"
#include "sysfs.h"

#include <jailhouse/header.h>
#include <jailhouse/hypercall.h>
#include <generated/version.h>

#ifdef CONFIG_X86_32
#error 64-bit kernel required!
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
#define MSR_IA32_FEAT_CTL			MSR_IA32_FEATURE_CONTROL
#define FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX \
	FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX
#endif

#if JAILHOUSE_CELL_ID_NAMELEN != JAILHOUSE_CELL_NAME_MAXLEN
# warning JAILHOUSE_CELL_ID_NAMELEN and JAILHOUSE_CELL_NAME_MAXLEN out of sync!
#endif

#ifdef CONFIG_X86
#define JAILHOUSE_AMD_FW_NAME	"jailhouse-amd.bin"
#define JAILHOUSE_INTEL_FW_NAME	"jailhouse-intel.bin"
#else
#define JAILHOUSE_FW_NAME	"jailhouse.bin"
#endif

MODULE_DESCRIPTION("Management driver for Jailhouse partitioning hypervisor");
MODULE_LICENSE("GPL");
#ifdef CONFIG_X86
MODULE_FIRMWARE(JAILHOUSE_AMD_FW_NAME);
MODULE_FIRMWARE(JAILHOUSE_INTEL_FW_NAME);
#else
MODULE_FIRMWARE(JAILHOUSE_FW_NAME);
#endif
MODULE_VERSION(JAILHOUSE_VERSION);

extern char __hyp_stub_vectors[];

struct console_state {
	unsigned int head;
	unsigned int last_console_id;
};

DEFINE_MUTEX(jailhouse_lock);
bool jailhouse_enabled;
void *hypervisor_mem;

static struct device *jailhouse_dev;
static unsigned long hv_core_and_percpu_size;
static atomic_t call_done;
static int error_code;
static struct jailhouse_virt_console* volatile console_page;
static bool console_available;
static struct resource *hypervisor_mem_res;

static typeof(ioremap_page_range) *ioremap_page_range_sym;
#ifdef CONFIG_X86
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0)
#define lapic_timer_period	lapic_timer_frequency
#define lapic_timer_period_sym	lapic_timer_frequency_sym
#endif
static typeof(lapic_timer_period) *lapic_timer_period_sym;
#endif
#ifdef CONFIG_ARM
static typeof(__boot_cpu_mode) *__boot_cpu_mode_sym;
#endif
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
static typeof(__hyp_stub_vectors) *__hyp_stub_vectors_sym;
#endif

/* last_console contains three members:
 *   - valid: indicates if content in the page member is present
 *   - id:    hint for the consumer if it already consumed the content
 *   - page:  actual content
 *
 * Those members are updated in following cases:
 *   - on disabling the hypervisor to print last messages
 *   - on failures when enabling the hypervisor
 *
 * We need this structure, as in those cases the hypervisor memory gets
 * unmapped.
 */
static struct {
	bool valid;
	unsigned int id;
	struct jailhouse_virt_console page;
} last_console;

#ifdef CONFIG_X86
bool jailhouse_use_vmcall;

static void init_hypercall(void)
{
	jailhouse_use_vmcall = boot_cpu_has(X86_FEATURE_VMX);
}
#else /* !CONFIG_X86 */
static void init_hypercall(void)
{
}
#endif

static void copy_console_page(struct jailhouse_virt_console *dst)
{
	unsigned int tail;

	do {
		/* spin while hypervisor is writing to console */
		while (console_page->busy)
			cpu_relax();
		tail = console_page->tail;
		rmb();

		/* copy console page */
		memcpy(dst, console_page,
		       sizeof(struct jailhouse_virt_console));
		rmb();
	} while (console_page->tail != tail || console_page->busy);
}

static inline void update_last_console(void)
{
	if (!console_available)
		return;

	copy_console_page(&last_console.page);
	last_console.id++;
	last_console.valid = true;
}

static long get_max_cpus(u32 cpu_set_size,
			 const struct jailhouse_system __user *system_config)
{
	u8 __user *cpu_set =
		(u8 __user *)jailhouse_cell_cpu_set(
				(const struct jailhouse_cell_desc * __force)
				&system_config->root_cell);
	unsigned int pos = cpu_set_size;
	long max_cpu_id;
	u8 bitmap;

	while (pos-- > 0) {
		if (get_user(bitmap, cpu_set + pos))
			return -EFAULT;
		max_cpu_id = fls(bitmap);
		if (max_cpu_id > 0)
			return pos * 8 + max_cpu_id;
	}
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
#define __get_vm_area(size, flags, start, end)			\
	__get_vm_area_caller(size, flags, start, end,		\
			     __builtin_return_address(0))
#endif

void *jailhouse_ioremap(phys_addr_t phys, unsigned long virt,
			unsigned long size)
{
	struct vm_struct *vma;

	size = PAGE_ALIGN(size);
	if (virt)
		vma = __get_vm_area(size, VM_IOREMAP, virt,
				    virt + size + PAGE_SIZE);
	else
		vma = __get_vm_area(size, VM_IOREMAP, VMALLOC_START,
				    VMALLOC_END);
	if (!vma)
		return NULL;
	vma->phys_addr = phys;

	if (ioremap_page_range_sym((unsigned long)vma->addr,
				   (unsigned long)vma->addr + size, phys,
				   PAGE_KERNEL_EXEC)) {
		vunmap(vma->addr);
		return NULL;
	}

	return vma->addr;
}

/*
 * Called for each cpu by the JAILHOUSE_ENABLE ioctl.
 * It jumps to the entry point set in the header, reports the result and
 * signals completion to the main thread that invoked it.
 */
static void enter_hypervisor(void *info)
{
	struct jailhouse_header *header = info;
	unsigned int cpu = smp_processor_id();
	int (*entry)(unsigned int);
	int err;

	entry = header->entry + (unsigned long) hypervisor_mem;			/* 计算hypervisor入口虚拟地址,实际为架构的entry.S中的arch_entry的地址 */

	if (cpu < header->max_cpus)
		/* either returns 0 or the same error code across all CPUs */
		err = entry(cpu);											/* 离开kernel module，进入到hypervisor入口 */
	else															/* entry函数执行完毕，Linux此时变成了Guest OS，运行在non-root模式下 */
		err = -EINVAL;

	if (err)
		error_code = err;

#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	/* on Intel, VMXE is now on - update the shadow */
	if (boot_cpu_has(X86_FEATURE_VMX) && !err) {						/* Linux此时已经变成了Guest，更新CR4的VMXE shadow，VMX实际已经在hypervisor中启用 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
		cr4_set_bits_irqsoff(X86_CR4_VMXE);
#else
		cr4_set_bits(X86_CR4_VMXE);
#endif
	}
#endif

	atomic_inc(&call_done);				/* 当前CPU初始化完成后将call_done计数加一 */
}

static inline const char * jailhouse_get_fw_name(void)
{
#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_SVM))
		return JAILHOUSE_AMD_FW_NAME;
	if (boot_cpu_has(X86_FEATURE_VMX))
		return JAILHOUSE_INTEL_FW_NAME;
	return NULL;
#else
	return JAILHOUSE_FW_NAME;
#endif
}

static int __jailhouse_console_dump_delta(struct jailhouse_virt_console
						*console,
					  char *dst, unsigned int head,
					  unsigned int *miss)
{
	int ret;
	unsigned int head_mod, tail_mod;
	unsigned int delta, missed = 0;

	/* we might underflow here intentionally */
	delta = console->tail - head;

	/* check if we have misses */
	if (delta > sizeof(console->content)) {
		missed = delta - sizeof(console->content);
		head = console->tail - sizeof(console->content);
		delta = sizeof(console->content);
	}

	head_mod = head % sizeof(console->content);
	tail_mod = console->tail % sizeof(console->content);

	if (head_mod + delta > sizeof(console->content)) {
		ret = sizeof(console->content) - head_mod;
		memcpy(dst, console->content + head_mod, ret);
		delta -= ret;
		memcpy(dst + ret, console->content, delta);
		ret += delta;
	} else {
		ret = delta;
		memcpy(dst, console->content + head_mod, delta);
	}

	if (miss)
		*miss = missed;

	return ret;
}

static void jailhouse_firmware_free(void)
{
	jailhouse_sysfs_core_exit(jailhouse_dev);
	if (hypervisor_mem_res) {
		release_mem_region(hypervisor_mem_res->start,
				   resource_size(hypervisor_mem_res));
		hypervisor_mem_res = NULL;
	}
	vunmap(hypervisor_mem);
	hypervisor_mem = NULL;
}

int jailhouse_console_dump_delta(char *dst, unsigned int head,
				 unsigned int *miss)
{
	int ret;
	struct jailhouse_virt_console *console;

	if (!jailhouse_enabled)
		return -EAGAIN;

	if (!console_available)
		return -EPERM;

	console = kmalloc(sizeof(struct jailhouse_virt_console), GFP_KERNEL);
	if (console == NULL)
		return -ENOMEM;

	copy_console_page(console);
	if (console->tail == head) {
		ret = 0;
		goto console_free_out;
	}

	ret = __jailhouse_console_dump_delta(console, dst, head, miss);

console_free_out:
	kfree(console);
	return ret;
}

/* See Documentation/bootstrap-interface.txt */
static int jailhouse_cmd_enable(struct jailhouse_system __user *arg)
{
	const struct firmware *hypervisor;
	struct jailhouse_system config_header;
	struct jailhouse_system *config;
	struct jailhouse_memory *hv_mem = &config_header.hypervisor_memory;
	struct jailhouse_header *header;
	unsigned long remap_addr = 0;
	void __iomem *console = NULL, *clock_reg = NULL;
	unsigned long config_size;
	unsigned int clock_gates;
	const char *fw_name;
	long max_cpus;
	int err;

	fw_name = jailhouse_get_fw_name();							/* 检查x86是否拥有vmx特性，对于ARM无操作，并返回JAILHOUSE_FW_NAME */
	if (!fw_name) {
		pr_err("jailhouse: Missing or unsupported HVM technology\n");
		return -ENODEV;
	}

	if (copy_from_user(&config_header, arg, sizeof(config_header)))		/* 将config的header读入，可以在工程的configs目录下找到jailhouse提供的config demo */
		return -EFAULT;

	if (memcmp(config_header.signature, JAILHOUSE_SYSTEM_SIGNATURE,		/* 比较config的签名是否正确 */
		   sizeof(config_header.signature)) != 0) {
		pr_err("jailhouse: Not a system configuration\n");
		return -EINVAL;
	}
	if (config_header.revision != JAILHOUSE_CONFIG_REVISION) {			/* 比较config和内核模块的版本是否一致 */
		pr_err("jailhouse: Configuration revision mismatch\n");
		return -EINVAL;
	}

	config_header.root_cell.name[JAILHOUSE_CELL_NAME_MAXLEN] = 0;

	max_cpus = get_max_cpus(config_header.root_cell.cpu_set_size, arg);		/* 获取linux包含的最大的CPU数量 */
	if (max_cpus < 0)
		return max_cpus;
	if (max_cpus > UINT_MAX)
		return -EINVAL;

	if (mutex_lock_interruptible(&jailhouse_lock) != 0)
		return -EINTR;

	err = -EBUSY;
	if (jailhouse_enabled || !try_module_get(THIS_MODULE))			/* 检查是否已经启用了jailhouse以及模块是否被正确加载 */
		goto error_unlock;

#ifdef CONFIG_ARM
	/* open-coded is_hyp_mode_available to use __boot_cpu_mode_sym */
	if ((*__boot_cpu_mode_sym & MODE_MASK) != HYP_MODE ||			/* 对于ARM，检查系统是否支持HYP mode */
	    (*__boot_cpu_mode_sym) & BOOT_CPU_MODE_MISMATCH) {
		pr_err("jailhouse: HYP mode not available\n");
		err = -ENODEV;
		goto error_put_module;
	}
#endif
#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_VMX)) {						/* 对于x86，检查系统是否支持vmx */
		u64 features;

		rdmsrl(MSR_IA32_FEAT_CTL, features);
		if ((features & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX) == 0) {		/* 检查vmx是否被BIOS禁用 */
			pr_err("jailhouse: VT-x disabled by Firmware/BIOS\n");
			err = -ENODEV;
			goto error_put_module;
		}
	}
#endif

	/* Load hypervisor image */
	err = request_firmware(&hypervisor, fw_name, jailhouse_dev);		/* 加载hypervisor */
	if (err) {
		pr_err("jailhouse: Missing hypervisor image %s\n", fw_name);
		goto error_put_module;
	}

	header = (struct jailhouse_header *)hypervisor->data;			

	err = -EINVAL;
	if (memcmp(header->signature, JAILHOUSE_SIGNATURE,			/* 比较hypervisor的签名是否正确 */
		   sizeof(header->signature)) != 0 ||
	    hypervisor->size >= hv_mem->size)
		goto error_release_fw;

	hv_core_and_percpu_size = header->core_size +					/* 计算hypervisor core和percpu区域的大小	*/
		max_cpus * header->percpu_size;								/* core包含了hypervisor的代码段和数据段   	*/
	config_size = jailhouse_system_config_size(&config_header);		/* percpu区域将用于存放hypervisor的栈等		*/
	if (hv_core_and_percpu_size >= hv_mem->size ||					/* hypervisor的memory layout可以在Documentation/memory-layout.txt中找到 */
	    config_size >= hv_mem->size - hv_core_and_percpu_size)
		goto error_release_fw;

#ifdef JAILHOUSE_BORROW_ROOT_PT
	remap_addr = JAILHOUSE_BASE;
#endif
	/* Unmap hypervisor_mem from a previous "enable". The mapping has to be
	 * redone since the root-cell config might have changed. */
	jailhouse_firmware_free();							

	hypervisor_mem_res = request_mem_region(hv_mem->phys_start,		/* 为hypervisor分配物理内存，该区域是预先留存给hypervisor的，通过kernel cmdline的memmap参数设置 */
						hv_mem->size,
						"Jailhouse hypervisor");
	if (!hypervisor_mem_res) {
		pr_err("jailhouse: request_mem_region failed for hypervisor "
		       "memory.\n");
		pr_notice("jailhouse: Did you reserve the memory with "
			  "\"memmap=\" or \"mem=\"?\n");
		goto error_release_fw;
	}

	/* Map physical memory region reserved for Jailhouse. */
	hypervisor_mem = jailhouse_ioremap(hv_mem->phys_start, remap_addr,		/* 给hypervisor的物理内存做虚拟内存映射 */
					   hv_mem->size);
	if (!hypervisor_mem) {
		pr_err("jailhouse: Unable to map RAM reserved for hypervisor "
		       "at %08lx\n", (unsigned long)hv_mem->phys_start);
		goto error_release_memreg;
	}

	console_page = (struct jailhouse_virt_console*)					/* 计算console的虚拟地址 */
		(hypervisor_mem + header->console_page);
	last_console.valid = false;

	/* Copy hypervisor's binary image at beginning of the memory region
	 * and clear the rest to zero. */
	memcpy(hypervisor_mem, hypervisor->data, hypervisor->size);		/* 将hypervisor整个加载到预留的物理内存上 */
	memset(hypervisor_mem + hypervisor->size, 0,					/* 将预留内存的其余区域初始化为0 */
	       hv_mem->size - hypervisor->size);

	header = (struct jailhouse_header *)hypervisor_mem;
	header->max_cpus = max_cpus;

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	header->arm_linux_hyp_vectors = virt_to_phys(*__hyp_stub_vectors_sym);		/* arm的HYP mode的异常处理向量地址，将在启用hypervisor时使用 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0)
	header->arm_linux_hyp_abi = HYP_STUB_ABI_LEGACY;
#else
	header->arm_linux_hyp_abi = HYP_STUB_ABI_OPCODE;
#endif
#endif

	err = jailhouse_sysfs_core_init(jailhouse_dev, header->core_size);			/* 创建hypervisor的binary文件，位于/sys/devices/jailhouse/core */ 
	if (err)
		goto error_unmap;

	/*
	 * ARMv8 requires to clean D-cache and invalidate I-cache for memory
	 * containing new instructions. On x86 this is a NOP. On ARMv7 the
	 * firmware does its own cache maintenance, so it is an
	 * extraneous (but harmless) flush.
	 */
	flush_icache_range((unsigned long)hypervisor_mem,
			   (unsigned long)(hypervisor_mem + header->core_size));

	/* Copy system configuration to its target address in hypervisor memory
	 * region. */
	config = (struct jailhouse_system *)
		(hypervisor_mem + hv_core_and_percpu_size);
	if (copy_from_user(config, arg, config_size)) {
		err = -EFAULT;
		goto error_unmap;
	}

	/* 主要是设置debug console的clock gate，与硬件特性相关，与hypervisor本身的功能无关 */
	if (config->debug_console.clock_reg) {
		clock_reg = ioremap(config->debug_console.clock_reg,
				    sizeof(clock_gates));
		if (!clock_reg) {
			err = -EINVAL;
			pr_err("jailhouse: Unable to map clock register at "
			       "%08lx\n",
			       (unsigned long)config->debug_console.clock_reg);
			goto error_unmap;
		}

		clock_gates = readl(clock_reg);
		if (CON_HAS_INVERTED_GATE(config->debug_console.flags))
			clock_gates &= ~(1 << config->debug_console.gate_nr);
		else
			clock_gates |= (1 << config->debug_console.gate_nr);
		writel(clock_gates, clock_reg);

		iounmap(clock_reg);
	}

#ifdef JAILHOUSE_BORROW_ROOT_PT
	if (CON_IS_MMIO(config->debug_console.flags)) {
		console = ioremap(config->debug_console.address,
				  config->debug_console.size);
		if (!console) {
			err = -EINVAL;
			pr_err("jailhouse: Unable to map hypervisor debug "
			       "console at %08lx\n",
			       (unsigned long)config->debug_console.address);
			goto error_unmap;
		}
		/* The hypervisor has no notion of address spaces, so we need
		 * to enforce conversion. */
		header->debug_console_base = (void * __force)console;
	}
#endif

	console_available = SYS_FLAGS_VIRTUAL_DEBUG_CONSOLE(config->flags);

#ifdef CONFIG_X86
	if (config->platform_info.x86.tsc_khz == 0)
		config->platform_info.x86.tsc_khz = tsc_khz;
	if (config->platform_info.x86.apic_khz == 0)
		config->platform_info.x86.apic_khz =
			*lapic_timer_period_sym / (1000 / HZ);
#endif

	err = jailhouse_cell_prepare_root(&config->root_cell);		/* 创建root cell，主要是初始化root cell的cell描述符, */ 
	if (err)													/* 分配数据结构空间，还有注册PCI设备和创建sysfs */
		goto error_unmap;

	error_code = 0;

	preempt_disable();

	header->online_cpus = num_online_cpus();

	/*
	 * Cannot use wait=true here because all CPUs have to enter the
	 * hypervisor to start the handover while on_each_cpu holds the calling
	 * CPU back.
	 */
	atomic_set(&call_done, 0);
	on_each_cpu(enter_hypervisor, header, 0);					/* 进入hypervisor,计算hypervisor入口, */
	while (atomic_read(&call_done) != num_online_cpus())		/* 并跳转到架构的entry.S文件的arch_entry处 */
		cpu_relax();											/* 每个CPU都会将call_done计数加一，只有当call_done等于online的CPU数量时, */
																/* 初始化才算完成。否则当前CPU必须等待其他CPU完成 */
	preempt_enable();

	if (error_code) {
		err = error_code;
		goto error_free_cell;
	}

	if (console)
		iounmap(console);

	release_firmware(hypervisor);

	jailhouse_cell_register_root();								/* 将root cell添加到cell的链表上，并注册相应的sysfs */
	jailhouse_pci_virtual_root_devices_add(&config_header);		/* 向host上添加虚拟PCI设备 */

	jailhouse_enabled = true;

	mutex_unlock(&jailhouse_lock);

	pr_info("The Jailhouse is opening.\n");

	return 0;

error_free_cell:
	update_last_console();
	jailhouse_cell_delete_root();

error_unmap:
	jailhouse_firmware_free();
	if (console)
		iounmap(console);

error_release_memreg:
	/* jailhouse_firmware_free() could have been called already and
	 * has released hypervisor_mem_res. */
	if (hypervisor_mem_res)
		release_mem_region(hypervisor_mem_res->start,
				resource_size(hypervisor_mem_res));
	hypervisor_mem_res = NULL;

error_release_fw:
	release_firmware(hypervisor);

error_put_module:
	module_put(THIS_MODULE);

error_unlock:
	mutex_unlock(&jailhouse_lock);
	return err;
}

static void leave_hypervisor(void *info)
{
	void *page;
	int err;

	/* Touch each hypervisor page we may need during the switch so that
	 * the active mm definitely contains all mappings. At least x86 does
	 * not support taking any faults while switching worlds. */
	for (page = hypervisor_mem;
	     page < hypervisor_mem + hv_core_and_percpu_size;
	     page += PAGE_SIZE)
		readl((void __iomem *)page);

	/* either returns 0 or the same error code across all CPUs */
	err = jailhouse_call(JAILHOUSE_HC_DISABLE);
	if (err)
		error_code = err;

#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	/* on Intel, VMXE is now off - update the shadow */
	if (boot_cpu_has(X86_FEATURE_VMX) && !err) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,5,0)
		cr4_clear_bits_irqsoff(X86_CR4_VMXE);
#else
		cr4_clear_bits(X86_CR4_VMXE);
#endif
	}
#endif

	atomic_inc(&call_done);
}

static int jailhouse_cmd_disable(void)
{
	int err;

	if (mutex_lock_interruptible(&jailhouse_lock) != 0)
		return -EINTR;

	if (!jailhouse_enabled) {
		err = -EINVAL;
		goto unlock_out;
	}

	err = jailhouse_cmd_cell_destroy_non_root();
	if (err)
		goto unlock_out;

	jailhouse_pci_virtual_root_devices_remove();

	error_code = 0;

	preempt_disable();

	if (num_online_cpus() != cpumask_weight(&root_cell->cpus_assigned)) {
		/*
		 * Not all assigned CPUs are currently online. If we disable
		 * now, we will lose the offlined ones.
		 */

		preempt_enable();

		err = -EBUSY;
		goto unlock_out;
	}

#ifdef CONFIG_ARM
	/*
	 * This flag has been set when onlining a CPU under Jailhouse
	 * supervision into SVC instead of HYP mode.
	 */
	*__boot_cpu_mode_sym &= ~BOOT_CPU_MODE_MISMATCH;
#endif

	atomic_set(&call_done, 0);
	/* See jailhouse_cmd_enable while wait=true does not work. */
	on_each_cpu(leave_hypervisor, NULL, 0);
	while (atomic_read(&call_done) != num_online_cpus())
		cpu_relax();

	preempt_enable();

	err = error_code;
	if (err)
		goto unlock_out;

	update_last_console();

	jailhouse_cell_delete_root();
	jailhouse_enabled = false;
	module_put(THIS_MODULE);

	pr_info("The Jailhouse was closed.\n");

unlock_out:
	mutex_unlock(&jailhouse_lock);

	return err;
}

static long jailhouse_ioctl(struct file *file, unsigned int ioctl,
			    unsigned long arg)
{
	long err;

	switch (ioctl) {
	case JAILHOUSE_ENABLE:
		err = jailhouse_cmd_enable(
			(struct jailhouse_system __user *)arg);
		break;
	case JAILHOUSE_DISABLE:
		err = jailhouse_cmd_disable();
		break;
	case JAILHOUSE_CELL_CREATE:
		err = jailhouse_cmd_cell_create(
			(struct jailhouse_cell_create __user *)arg);
		break;
	case JAILHOUSE_CELL_LOAD:
		err = jailhouse_cmd_cell_load(
			(struct jailhouse_cell_load __user *)arg);
		break;
	case JAILHOUSE_CELL_START:
		err = jailhouse_cmd_cell_start((const char __user *)arg);
		break;
	case JAILHOUSE_CELL_DESTROY:
		err = jailhouse_cmd_cell_destroy((const char __user *)arg);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static int jailhouse_console_open(struct inode *inode, struct file *file)
{
	struct console_state *user;

	user = kzalloc(sizeof(struct console_state), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	file->private_data = user;

	return 0;
}

static int jailhouse_console_release(struct inode *inode, struct file *file)
{
	struct console_state *user = file->private_data;

	kfree(user);

	return 0;
}

static ssize_t jailhouse_console_read(struct file *file, char __user *out,
				      size_t size, loff_t *off)
{
	struct console_state *user = file->private_data;
	char *content;
	unsigned int miss;
	int ret;

	content = kmalloc(sizeof(console_page->content), GFP_KERNEL);
	if (content == NULL)
		return -ENOMEM;

	/* wait for new data */
	while (1) {
		if (mutex_lock_interruptible(&jailhouse_lock) != 0) {
			ret = -EINTR;
			goto console_free_out;
		}

		if (last_console.id != user->last_console_id &&
		    last_console.valid) {
			ret = __jailhouse_console_dump_delta(&last_console.page,
							     content,
							     user->head,
							     &miss);
			if (!ret)
				user->last_console_id =
					last_console.id;
		} else {
			ret = jailhouse_console_dump_delta(content, user->head,
							   &miss);
		}

		mutex_unlock(&jailhouse_lock);

		if ((!ret || ret == -EAGAIN) && file->f_flags & O_NONBLOCK)
			goto console_free_out;

		if (ret == -EAGAIN)
			/* Reset the user head, if jailhouse is not enabled. We
			 * have to do this, as jailhouse might be reenabled and
			 * the file handle was kept open in the meanwhile */
			user->head = 0;
		else if (ret < 0)
			goto console_free_out;
		else if (ret)
			break;

		schedule_timeout_uninterruptible(HZ / 10);
		if (signal_pending(current)) {
			ret = -EINTR;
			goto console_free_out;
		}
	}

	if (miss) {
		/* If we missed anything, warn user. We will dump the actual
		 * content in the next call. */
		ret = snprintf(content, sizeof(console_page->content),
			       "<missed %u bytes of console log>\n",
			       miss);
		user->head += miss;
		if (size < ret)
			ret = size;
	} else {
		if (size < ret)
			ret = size;
		user->head += ret;
	}

	if (copy_to_user(out, content, ret))
		ret = -EFAULT;

console_free_out:
	set_current_state(TASK_RUNNING);
	kfree(content);
	return ret;
}


static const struct file_operations jailhouse_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = jailhouse_ioctl,
	.compat_ioctl = jailhouse_ioctl,
	.llseek = noop_llseek,
	.open = jailhouse_console_open,
	.release = jailhouse_console_release,
	.read = jailhouse_console_read,
};

static struct miscdevice jailhouse_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "jailhouse",
	.fops = &jailhouse_fops,
};

static int jailhouse_shutdown_notify(struct notifier_block *unused1,
				     unsigned long unused2, void *unused3)
{
	int err;

	err = jailhouse_cmd_disable();
	if (err && err != -EINVAL)
		pr_emerg("jailhouse: ordered shutdown failed!\n");

	return NOTIFY_DONE;
}

static struct notifier_block jailhouse_shutdown_nb = {
	.notifier_call = jailhouse_shutdown_notify,
};

static int __init jailhouse_init(void)
{
	int err;

#if defined(CONFIG_KALLSYMS_ALL) && LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)
#define __RESOLVE_EXTERNAL_SYMBOL(symbol)			\
	symbol##_sym = (void *)kallsyms_lookup_name(#symbol);	\
	if (!symbol##_sym)					\
		return -EINVAL
#else
#define __RESOLVE_EXTERNAL_SYMBOL(symbol)			\
	symbol##_sym = &symbol
#endif
#define RESOLVE_EXTERNAL_SYMBOL(symbol...) __RESOLVE_EXTERNAL_SYMBOL(symbol)

	RESOLVE_EXTERNAL_SYMBOL(ioremap_page_range);
#ifdef CONFIG_X86
	RESOLVE_EXTERNAL_SYMBOL(lapic_timer_period);
#endif
#ifdef CONFIG_ARM
	RESOLVE_EXTERNAL_SYMBOL(__boot_cpu_mode);
#endif
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	RESOLVE_EXTERNAL_SYMBOL(__hyp_stub_vectors);
#endif

	jailhouse_dev = root_device_register("jailhouse");		/* 注册root device，创建/sys/devices/jailhouse目录 */
	if (IS_ERR(jailhouse_dev))
		return PTR_ERR(jailhouse_dev);

	err = jailhouse_sysfs_init(jailhouse_dev);				/* 创建/sys/devices/jailhouse/cells目录 */
	if (err)
		goto unreg_dev;

	err = misc_register(&jailhouse_misc_dev);				/* 创建misc设备，主要用于提供用户态与hypervisor的交互的接口 */
	if (err)
		goto exit_sysfs;

	err = jailhouse_pci_register();							/* 创建一个伪PCI设备，用于将设备分配给非root cell使用 */
	if (err)
		goto exit_misc;

	register_reboot_notifier(&jailhouse_shutdown_nb);		/* 注册重启的notifier */

	init_hypercall();										/* 对于x86仅判断CPU是否支持VMX，对于ARM无操作 */

	return 0;
exit_misc:
	misc_deregister(&jailhouse_misc_dev);

exit_sysfs:
	jailhouse_sysfs_exit(jailhouse_dev);

unreg_dev:
	root_device_unregister(jailhouse_dev);
	return err;
}

static void __exit jailhouse_exit(void)
{
	unregister_reboot_notifier(&jailhouse_shutdown_nb);
	misc_deregister(&jailhouse_misc_dev);
	jailhouse_sysfs_exit(jailhouse_dev);
	jailhouse_firmware_free();
	jailhouse_pci_unregister();
	root_device_unregister(jailhouse_dev);
}

module_init(jailhouse_init);
module_exit(jailhouse_exit);
