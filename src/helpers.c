#include <assert.h>
#include <stdio.h>
#include "helpers.h"
#include "statistics.h"

static uint64_t vmcall4(unsigned long rax, unsigned long rbx, unsigned long rcx,
								unsigned long rdx, unsigned long rsi) {
	asm volatile(
		"vmcall \n\t"
		"mov %%rax, %0 \n\t"
		: "+a"(rax)
		: "b"(rbx), "c"(rcx), "d"(rdx), "S"(rsi)
		:
	);
	return rax;
}

uintptr_t hc_find_magic(uint64_t magic)
{
	return vmcall4(97, 101, magic, 0, 0);
}

int hc_single_task_running(void)
{
	return vmcall4(97, 102, 0, 0, 0);
}

uint64_t hc_read_pa(uintptr_t pa)
{
	return vmcall4(97, 103, pa, 0, 0);
}

uintptr_t hc_phys_map_base(void)
{
	return vmcall4(97, 104, 0, 0, 0);
}

uintptr_t hc_direct_map(void)
{
	return vmcall4(97, 105, 0, 0, 0);
}

uint64_t hc_read_va(uintptr_t va)
{
	return vmcall4(97, 106, va, 0, 0);
}

uintptr_t hc_translate_va(uintptr_t va)
{
	return vmcall4(97, 107, va, 0, 0);
}

uintptr_t helper_find_page_pa(void *page)
{
	uint64_t *p = (uint64_t *)page;
	uintptr_t pa;
	do {
		*p = rand64();
		pa = hc_find_magic(*p);
		assert(hc_read_pa(pa) == *p);
		*p = rand64();
	} while (hc_read_pa(pa) != *p);
	return pa;
}

uintptr_t helper_base_pa(void)
{
	return hc_phys_map_base() - hc_direct_map();
}
