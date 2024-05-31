#pragma once
#if __has_include(<stddef.h>)
#include <stddef.h>
#else
#include <linux/types.h>
#endif

void build_eviction_sets(void);
void evict_l2(const size_t l2_set);
void free_eviction_sets(void);
