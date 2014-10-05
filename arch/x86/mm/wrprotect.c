/* wrprotect.c - Kernel space write protection support
 * Copyright (C) 2012 Hitachi, Ltd.
 * Author: YOSHIDA Masanori <masanori.yoshida.tv@hitachi.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#include <asm/wrprotect.h>
#include <linux/mm.h>		/* num_physpages, __get_free_page, etc. */
#include <linux/bitmap.h>	/* bit operations */
#include <linux/vmalloc.h>	/* vzalloc, vfree */
#include <linux/hugetlb.h>	/* __flush_tlb_all */
#include <linux/stop_machine.h>	/* stop_machine */
#include <asm/sections.h>	/* __per_cpu_* */

int wrprotect_is_on;

/* wrprotect's stuffs */
static struct wrprotect {
	int state;
#define STATE_UNINIT 0
#define STATE_INITED 1
#define STATE_STARTED 2
#define STATE_SWEPT 3

	unsigned long *pgbmp;
#define PGBMP_LEN PAGE_ALIGN(sizeof(long) * BITS_TO_LONGS(num_physpages))

	fn_handle_page_t handle_page;
} __aligned(PAGE_SIZE) wrprotect;

/* split_large_pages
 *
 * This function splits all large pages in straight mapping area into 4K ones.
 * Currently wrprotect supports only 4K pages, and so this is needed.
 */
static int split_large_pages(void)
{
	unsigned long pfn;
	for (pfn = 0; pfn < num_physpages; pfn++) {
		int ret = set_memory_4k((unsigned long)pfn_to_kaddr(pfn), 1);
		if (ret)
			return ret;
	}
	return 0;
}

struct sm_context {
	int leader_cpu;
	int leader_done;
	int (*fn_leader)(void *arg);
	int (*fn_follower)(void *arg);
	void *arg;
};

static int call_leader_follower(void *data)
{
	int ret;
	struct sm_context *ctx = data;

	if (smp_processor_id() == ctx->leader_cpu) {
		ret = ctx->fn_leader(ctx->arg);
		ctx->leader_done = 1;
	} else {
		while (!ctx->leader_done)
			cpu_relax();
		ret = ctx->fn_follower(ctx->arg);
	}

	return ret;
}

/* stop_machine_leader_follower
 *
 * Calls stop_machine with a leader CPU and follower CPUs
 * executing different codes.
 * At first, the leader CPU is selected randomly and executes its code.
 * After that, follower CPUs execute their codes.
 */
static int stop_machine_leader_follower(
		int (*fn_leader)(void *),
		int (*fn_follower)(void *),
		void *arg)
{
	int cpu;
	struct sm_context ctx;

	preempt_disable();
	cpu = smp_processor_id();
	preempt_enable();

	memset(&ctx, 0, sizeof(ctx));
	ctx.leader_cpu = cpu;
	ctx.leader_done = 0;
	ctx.fn_leader = fn_leader;
	ctx.fn_follower = fn_follower;
	ctx.arg = arg;

	return stop_machine(call_leader_follower, &ctx, cpu_online_mask);
}

/* wrprotect_unselect_pages
 *
 * This function clears bits corresponding to pages that cover a range
 * from start to start+len.
 */
void wrprotect_unselect_pages(
		unsigned long *bmp,
		unsigned long start,
		unsigned long len)
{
	unsigned long addr;

	BUG_ON(start & ~PAGE_MASK);
	BUG_ON(len & ~PAGE_MASK);

	for (addr = start; addr < start + len; addr += PAGE_SIZE) {
		unsigned long pfn = __pa(addr) >> PAGE_SHIFT;
		clear_bit(pfn, bmp);
	}
}

/* handle_addr_range
 *
 * This function executes wrprotect.handle_page in turns against pages that
 * cover a range from start to start+len.
 * At the same time, it clears bits corresponding to the pages.
 */
static void handle_addr_range(unsigned long start, unsigned long len)
{
	unsigned long end = start + len;

	while (start < end) {
		unsigned long pfn = __pa(start) >> PAGE_SHIFT;
		if (test_bit(pfn, wrprotect.pgbmp)) {
			wrprotect.handle_page(pfn, 0);
			clear_bit(pfn, wrprotect.pgbmp);
		}
		start += PAGE_SIZE;
	}
}

/* handle_task
 *
 * This function executes handle_addr_range against task_struct & thread_info.
 */
static void handle_task(struct task_struct *t)
{
	BUG_ON(!t);
	BUG_ON(!t->stack);
	BUG_ON((unsigned long)t->stack & ~PAGE_MASK);
	handle_addr_range((unsigned long)t, sizeof(*t));
	handle_addr_range((unsigned long)t->stack, THREAD_SIZE);
}

/* handle_tasks
 *
 * This function executes handle_task against all tasks (including idle_task).
 */
static void handle_tasks(void)
{
	struct task_struct *p, *t;
	unsigned int cpu;

	do_each_thread(p, t) {
		handle_task(t);
	} while_each_thread(p, t);

	for_each_online_cpu(cpu)
		handle_task(idle_task(cpu));
}

static void handle_pmd(pmd_t *pmd)
{
	unsigned long i;

	handle_addr_range((unsigned long)pmd, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_PMD; i++) {
		if (pmd_present(pmd[i]) && !pmd_large(pmd[i]))
			handle_addr_range(pmd_page_vaddr(pmd[i]), PAGE_SIZE);
	}
}

static void handle_pud(pud_t *pud)
{
	unsigned long i;

	handle_addr_range((unsigned long)pud, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_PUD; i++) {
		if (pud_present(pud[i]) && !pud_large(pud[i]))
			handle_pmd((pmd_t *)pud_page_vaddr(pud[i]));
	}
}

/* handle_page_table
 *
 * This function executes wrprotect.handle_page against all pages that make up
 * page table structure and clears all bits corresponding to the pages.
 */
static void handle_page_table(void)
{
	pgd_t *pgd;
	unsigned long i;

	pgd = __va(read_cr3() & PAGE_MASK);
	handle_addr_range((unsigned long)pgd, PAGE_SIZE);
	for (i = pgd_index(PAGE_OFFSET); i < PTRS_PER_PGD; i++) {
		if (pgd_present(pgd[i]))
			handle_pud((pud_t *)pgd_page_vaddr(pgd[i]));
	}
}

/* handle_sensitive_pages
 *
 * This function executes wrprotect.handle_page against the following pages and
 * clears bits corresponding to them.
 * - All pages that include task_struct & thread_info
 * - All pages that make up page table structure
 * - All pages that include per_cpu variables
 * - All pages that cover kernel's data section
 */
static void handle_sensitive_pages(void)
{
	handle_tasks();
	handle_page_table();
	handle_addr_range((unsigned long)__per_cpu_offset[0], PMD_PAGE_SIZE);
	handle_addr_range((unsigned long)_sdata, _end - _sdata);
}

/* protect_page
 *
 * Changes a specified page's _PAGE_RW flag and _PAGE_UNUSED1 flag.
 * If the argument protect is non-zero:
 *  - _PAGE_RW flag is cleared
 *  - _PAGE_UNUSED1 flag is set
 * If the argument protect is zero:
 *  - _PAGE_RW flag is set
 *  - _PAGE_UNUSED1 flag is cleared
 *
 * The change is executed only when all the following are true.
 *  - The page is mapped by the straight mapping area.
 *  - The page is mapped as 4K page.
 *  - The page is originally writable.
 *
 * Returns 1 if the change is actually executed, otherwise returns 0.
 */
static int protect_page(unsigned long pfn, int protect)
{
	unsigned long addr = (unsigned long)pfn_to_kaddr(pfn);
	pte_t *ptep, pte;
	unsigned int level;

	ptep = lookup_address(addr, &level);
	if (WARN(!ptep, "livedump: Page=%016lx isn't mapped.\n", addr) ||
	    WARN(!pte_present(*ptep),
		    "livedump: Page=%016lx isn't mapped.\n", addr) ||
	    WARN(PG_LEVEL_NONE == level,
		    "livedump: Page=%016lx isn't mapped.\n", addr) ||
	    WARN(PG_LEVEL_2M == level,
		    "livedump: Page=%016lx is consisted of 2M page.\n", addr) ||
	    WARN(PG_LEVEL_1G == level,
		    "livedump: Page=%016lx is consisted of 1G page.\n", addr)) {
		return 0;
	}

	pte = *ptep;
	if (protect) {
		if (pte_write(pte)) {
			pte = pte_wrprotect(pte);
			pte = pte_set_flags(pte, _PAGE_UNUSED1);
		}
	} else {
		pte = pte_mkwrite(pte);
		pte = pte_clear_flags(pte, _PAGE_UNUSED1);
	}
	*ptep = pte;

	return 1;
}

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found	1: protection fault
 *   bit 1 ==	 0: read access		1: write access
 *   bit 2 ==	 0: kernel-mode access	1: user-mode access
 *   bit 3 ==				1: use of reserved bit detected
 *   bit 4 ==				1: fault was an instruction fetch
 */
enum x86_pf_error_code {
	PF_PROT		=		1 << 0,
	PF_WRITE	=		1 << 1,
	PF_USER		=		1 << 2,
	PF_RSVD		=		1 << 3,
	PF_INSTR	=		1 << 4,
};

int wrprotect_page_fault_handler(unsigned long error_code)
{
	pte_t *ptep, pte;
	unsigned int level;
	unsigned long pfn;

	/*
	 * Handle only kernel-mode write access
	 *
	 * error_code must be:
	 *  (1) PF_PROT
	 *  (2) PF_WRITE
	 *  (3) not PF_USER
	 *  (4) not PF_SRVD
	 *  (5) not PF_INSTR
	 */
	if (!(PF_PROT  & error_code) ||
	    !(PF_WRITE & error_code) ||
	     (PF_USER  & error_code) ||
	     (PF_RSVD  & error_code) ||
	     (PF_INSTR & error_code))
		goto not_processed;

	ptep = lookup_address(read_cr2(), &level);
	if (!ptep)
		goto not_processed;
	pte = *ptep;
	if (!pte_present(pte) || PG_LEVEL_4K != level)
		goto not_processed;
	if (!(pte_flags(pte) & _PAGE_UNUSED1))
		goto not_processed;

	pfn = pte_pfn(pte);
	if (test_and_clear_bit(pfn, wrprotect.pgbmp)) {
		wrprotect.handle_page(pfn, 0);
		protect_page(pfn, 0);
	}

	return true;

not_processed:
	return false;
}

/* sm_leader
 *
 * Is executed by a leader CPU during stop-machine.
 *
 * This function does the following:
 * (1)Handle pages that must not be write-protected.
 * (2)Turn on the callback in the page fault handler.
 * (3)Write-protect pages which are specified by the bitmap.
 * (4)Flush TLB cache of the leader CPU.
 */
static int sm_leader(void *arg)
{
	unsigned long pfn;

	handle_sensitive_pages();

	wrprotect_is_on = true;

	for_each_set_bit(pfn, wrprotect.pgbmp, num_physpages)
		if (!protect_page(pfn, 1))
			clear_bit(pfn, wrprotect.pgbmp);

	__flush_tlb_all();

	return 0;
}

/* sm_follower
 *
 * Is executed by follower CPUs during stop-machine.
 * Flushes TLB cache of each CPU.
 */
static int sm_follower(void *arg)
{
	__flush_tlb_all();
	return 0;
}

/* wrprotect_start
 *
 * This function sets up write protection on the kernel space during the
 * stop-machine state.
 */
int wrprotect_start(void)
{
	int ret;

	if (WARN(STATE_INITED != wrprotect.state,
				"livedump: wrprotect isn't initialized yet.\n"))
		return 0;

	ret = stop_machine_leader_follower(sm_leader, sm_follower, NULL);
	if (WARN(ret, "livedump: Failed to protect pages w/errno=%d.\n", ret))
		return ret;

	wrprotect.state = STATE_STARTED;
	return 0;
}

/* wrprotect_sweep
 *
 * On every page specified by the bitmap, this function executes the following.
 *  - Handle the page by calling wrprotect.handle_page.
 *  - Unprotect the page by calling protect_page.
 *
 * The above work may be executed on the same page at the same time
 * by the notifer-call-chain.
 * test_and_clear_bit is used for exclusion control.
 */
int wrprotect_sweep(void)
{
	unsigned long pfn;

	if (WARN(STATE_STARTED != wrprotect.state,
				"livedump: Pages aren't protected yet.\n"))
		return 0;
	for_each_set_bit(pfn, wrprotect.pgbmp, num_physpages) {
		if (!test_and_clear_bit(pfn, wrprotect.pgbmp))
			continue;
		wrprotect.handle_page(pfn, 1);
		protect_page(pfn, 0);
		if (!(pfn & 0xffUL))
			cond_resched();
	}
	wrprotect.state = STATE_SWEPT;
	return 0;
}

/* wrprotect_create_page_bitmap
 *
 * This function creates bitmap of which each bit corresponds to physical page.
 * Here, all ram pages are selected as being write-protected.
 */
unsigned long *wrprotect_create_page_bitmap(void)
{
	unsigned long *bmp;
	unsigned long pfn;

	/* allocate on vmap area */
	bmp = vzalloc(PGBMP_LEN);
	if (!bmp)
		return NULL;

	/* select all ram pages */
	for (pfn = 0; pfn < num_physpages; pfn++) {
		if (e820_any_mapped(pfn << PAGE_SHIFT,
				    (pfn + 1) << PAGE_SHIFT,
				    E820_RAM))
			set_bit(pfn, bmp);
		if (!(pfn & 0xffUL))
			cond_resched();
	}

	return bmp;
}

/* wrprotect_destroy_page_bitmap
 *
 * This function frees the page bitmap created by wrprotect_create_page_bitmap.
 */
void wrprotect_destroy_page_bitmap(unsigned long *bmp)
{
	vfree(bmp);
}

static void default_handle_page(unsigned long pfn, int for_sweep)
{
}

/* wrprotect_init
 *
 * pgbmp:
 *   This is a bitmap of which each bit corresponds to a physical page.
 *   Marked pages are write protected (or handled during stop-machine).
 *
 * fn_handle_page:
 *   This callback is invoked to handle faulting pages.
 *   This function takes 2 arguments.
 *   First one is PFN that tells which page caused page fault.
 *   Second one is a flag that tells whether it's called in the sweep phase.
 */
int wrprotect_init(unsigned long *pgbmp, fn_handle_page_t fn_handle_page)
{
	int ret;

	if (WARN(STATE_UNINIT != wrprotect.state,
			"livedump: wrprotect is already initialized.\n"))
		return 0;

	/* split all large pages in straight mapping area */
	ret = split_large_pages();
	if (ret)
		goto err;

	/* unselect internal stuffs of wrprotect */
	wrprotect_unselect_pages(
			pgbmp, (unsigned long)&wrprotect, sizeof(wrprotect));

	wrprotect.pgbmp = pgbmp;
	wrprotect.handle_page = fn_handle_page ?: default_handle_page;

	wrprotect.state = STATE_INITED;
	return 0;

err:
	return ret;
}

void wrprotect_uninit(void)
{
	unsigned long pfn;

	if (STATE_UNINIT == wrprotect.state)
		return;

	if (STATE_STARTED == wrprotect.state) {
		for_each_set_bit(pfn, wrprotect.pgbmp, num_physpages) {
			if (!test_and_clear_bit(pfn, wrprotect.pgbmp))
				continue;
			protect_page(pfn, 0);
			cond_resched();
		}

		flush_tlb_all();
	}

	if (STATE_STARTED <= wrprotect.state)
		wrprotect_is_on = false;

	wrprotect.pgbmp = NULL;
	wrprotect.handle_page = NULL;

	wrprotect.state = STATE_UNINIT;
}
