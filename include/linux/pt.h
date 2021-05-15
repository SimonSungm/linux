/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013-2017
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Alternatively, you can use or redistribute this file under the following
 * BSD license:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * As this is never called on a CPU without VM extensions,
 * we assume that where VMCALL isn't available, VMMCALL is.
 */
#ifndef _PT_H
#define _PT_H

#include <linux/types.h>
#include <linux/list.h>

struct px_memory_region {
	unsigned long start;
	unsigned long end;
	struct list_head list;
	char *name;
};

#define JAILHOUSE_HC_DISABLE			0
#define JAILHOUSE_HC_CELL_CREATE		1
#define JAILHOUSE_HC_CELL_START			2
#define JAILHOUSE_HC_CELL_SET_LOADABLE		3
#define JAILHOUSE_HC_CELL_DESTROY		4
#define JAILHOUSE_HC_HYPERVISOR_GET_INFO	5
#define JAILHOUSE_HC_CELL_GET_STATE		6
#define JAILHOUSE_HC_CPU_GET_INFO		7
#define JAILHOUSE_HC_DEBUG_CONSOLE_PUTC		8
#define JAILHOUSE_HC_GPHYS2PHYS_PXN 	9
#define JAILHOUSE_HC_WRITE_LONG		10
#define JAILHOUSE_HC_MEMCPY	0x80000000
#define JAILHOUSE_HC_MEMSET	0x40000000

#define SET_MEM_RO 5
#define SET_MEM_RW 6

int pt_add_mem_region(unsigned long start, unsigned long end, char *name);
int pt_add_mem_region_size(unsigned long start, unsigned long size, char *name);

#ifdef CONFIG_X86
#define JAILHOUSE_CALL_CODE_CUSTOM	\
	"vmcall"

#define JAILHOUSE_CALL_RESULT	"=a" (result)
#define JAILHOUSE_CALL_NUM	"a" (num)
#define JAILHOUSE_CALL_ARG1	"D" (arg1)
#define JAILHOUSE_CALL_ARG2	"S" (arg2)

/**
 * @defgroup Hypercalls Hypercall Subsystem
 *
 * The hypercall subsystem provides an interface for cells to invoke Jailhouse
 * services and interact via the communication region.
 *
 * @{
 */

/**
 * This variable selects the x86 hypercall instruction to be used by
 * jailhouse_call(), jailhouse_call_arg1(), and jailhouse_call_arg2().
 * A caller should define and initialize the variable before calling
 * any of these functions.
 *
 * @li @c false Use AMD's VMMCALL.
 * @li @c true Use Intel's VMCALL.
 */

/**
 * Invoke a hypervisor without additional arguments.
 * @param num		Hypercall number.
 *
 * @return Result of the hypercall, semantic depends on the invoked service.
 */
static inline __u32 jailhouse_call_custom(__u32 num)
{
	__u32 result;

	asm volatile(JAILHOUSE_CALL_CODE_CUSTOM
		: JAILHOUSE_CALL_RESULT
		: JAILHOUSE_CALL_NUM
		: "memory");
	return result;
}

/**
 * Invoke a hypervisor with one argument.
 * @param num		Hypercall number.
 * @param arg1		First argument.
 *
 * @return Result of the hypercall, semantic depends on the invoked service.
 */
static inline __u32 jailhouse_call_arg1_custom(__u32 num, unsigned long arg1)
{
	__u32 result;

	asm volatile(JAILHOUSE_CALL_CODE_CUSTOM
		: JAILHOUSE_CALL_RESULT
		: JAILHOUSE_CALL_NUM, JAILHOUSE_CALL_ARG1
		: "memory");
	return result;
}

/**
 * Invoke a hypervisor with two arguments.
 * @param num		Hypercall number.
 * @param arg1		First argument.
 * @param arg2		Second argument.
 *
 * @return Result of the hypercall, semantic depends on the invoked service.
 */
static inline __u32 jailhouse_call_arg2_custom(__u32 num, unsigned long arg1,
					unsigned long arg2)
{
	__u32 result;

	asm volatile(JAILHOUSE_CALL_CODE_CUSTOM
		: JAILHOUSE_CALL_RESULT
		: JAILHOUSE_CALL_NUM, JAILHOUSE_CALL_ARG1, JAILHOUSE_CALL_ARG2
		: "memory");
	return result;
}
#endif
#ifdef CONFIG_ARM64
#define JAILHOUSE_HVC_CODE		0x4a48
#define JAILHOUSE_CALL_INS		"hvc #0x4a48"
#define JAILHOUSE_CALL_NUM_RESULT	"x0"
#define JAILHOUSE_CALL_ARG1		"x1"
#define JAILHOUSE_CALL_ARG2		"x2"
#define JAILHOUSE_CALL_CLOBBERED	"x3"

static inline u32 jailhouse_call_custom(u32 num)
{
	register u32 num_result asm(JAILHOUSE_CALL_NUM_RESULT) = num;

	asm volatile(
		JAILHOUSE_CALL_INS
		: "+r" (num_result)
		: : "memory", JAILHOUSE_CALL_ARG1, JAILHOUSE_CALL_ARG2,
		    JAILHOUSE_CALL_CLOBBERED);
	return num_result;
}

static inline u32 jailhouse_call_arg1_custom(u32 num, u32 arg1)
{
	register u32 num_result asm(JAILHOUSE_CALL_NUM_RESULT) = num;
	register u32 __arg1 asm(JAILHOUSE_CALL_ARG1) = arg1;

	asm volatile(
		JAILHOUSE_CALL_INS
		: "+r" (num_result), "+r" (__arg1)
		: : "memory", JAILHOUSE_CALL_ARG2, JAILHOUSE_CALL_CLOBBERED);
	return num_result;
}

static inline u32 jailhouse_call_arg2_custom(u32 num, u32 arg1,
					   u32 arg2)
{
	register u32 num_result asm(JAILHOUSE_CALL_NUM_RESULT) = num;
	register u32 __arg1 asm(JAILHOUSE_CALL_ARG1) = arg1;
	register u32 __arg2 asm(JAILHOUSE_CALL_ARG2) = arg2;

	asm volatile(
		JAILHOUSE_CALL_INS
		: "+r" (num_result), "+r" (__arg1), "+r" (__arg2)
		: : "memory", JAILHOUSE_CALL_CLOBBERED);
	return num_result;
}
#endif
/** @} **/
#endif