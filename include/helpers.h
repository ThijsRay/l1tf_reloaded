#pragma once
#include <stdint.h>

uintptr_t hc_find_magic(uint64_t magic);
int hc_single_task_running(void);
uint64_t hc_read_pa(uintptr_t pa);
uintptr_t hc_phys_map_base(void);
uintptr_t hc_direct_map(void);
uint64_t hc_read_va(uintptr_t va);
uintptr_t hc_translate_va(uintptr_t va);
uintptr_t helper_find_page_pa(void *page);
uintptr_t helper_base_pa(void);
