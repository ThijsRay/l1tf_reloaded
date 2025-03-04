#pragma once
#define PAGE_SIZE (4096)
#define HUGE_PAGE_SIZE (2 * 1024*1024)
#define VALUES_IN_BYTE (256)

#define L1_SETS (64)
#define L1_WAYS (8)
#define L2_SETS (1024)
#define L2_WAYS (4)
#define CACHE_LINE_SIZE (64)

#define CPU 0

#define CACHE_HIT_THRESHOLD (160)

#define HOST_MEMORY_SIZE (625 * 1024ULL*1024*1024)

#define STRIDE (PAGE_SIZE + CACHE_LINE_SIZE)
