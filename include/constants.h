#pragma once
#define PAGE_SIZE (4096)
#define HUGE_PAGE_SIZE (2097152) // 2MiB
#define VALUES_IN_BYTE (256)

#define L1_SETS (64)
#define L1_WAYS (8)
#define L2_SETS (1024)
#define L2_WAYS (4)
#define CACHE_LINE_SIZE (64)

// 32 GiB
#define HOST_MEMORY_SIZE (34359738368)
