#pragma once
#include <stdio.h>
#include "config.h"
#include "reverse.h"

#define STR(a) STRSTR(a)
#define STRSTR(a) #a
#define dump(x) printf("%30s = %16lx\n", STR(x), x)
#define dumpp(x) printf("\t%30s = %16lx\n", STR(x), x)
#define BITS(x, n, m) ((x & BITS_MASK(n, m)) >> m)

void set_cpu_affinity(int cpu_id);
int get_sibling(int cpu_id);
uint64_t file_read_lx(const char *filename);
uint64_t file_write_lx(const char *filename, uint64_t uaddr);
uintptr_t procfs_direct_map(void);
uintptr_t procfs_pgd(void);
uintptr_t procfs_get_physaddr(gva_t uaddr);
u64 procfs_get_data(gva_t addr);
void print_page_table(hpa_t base, hpa_t page_table);
void dump_page_table_mappings(hpa_t base, hpa_t root_page_table, hpa_t eptp);
