#pragma once
#include <stdio.h>
#include "config.h"
#include "reverse.h"

#define CLEAR_LINE "\33[2K\r"
#define STR(a) STRSTR(a)
#define STRSTR(a) #a
#define dump(x) printf("%30s = %16lx\n", STR(x), x)
#define dumpp(x) printf("\t%30s = %16lx\n", STR(x), x)
#define BITS(x, n, m) ((x & BITS_MASK(n, m)) >> m)

/* for loop with iterator `name` ranging as:
 *      name = center
 *      name = center + step
 *      name = center - step
 *      name = center + 2*step
 *      name = center - 2*step
 *      ...
 */
#define for_each_around(name, center, radius, step) \
        for (long name = (center), delta = (step); name < (center) + (radius); name += delta, delta = -delta + (delta > 0 ? -(step) : (step)))

#define HLINE "--------------------------------------------------------------------------------\n"

void set_cpu_affinity(int cpu_id);
int get_sibling(int cpu_id);
uint64_t file_read_lx(const char *filename);
uint64_t file_write_lx(const char *filename, uint64_t uaddr);
uintptr_t procfs_direct_map(void);
uintptr_t procfs_pgd(void);
uintptr_t procfs_get_physaddr(gva_t uaddr);
u64 procfs_get_data(gva_t addr);
void print_page_table(hpa_t base, hpa_t page_table);
void dump_page_table_mappings(hpa_t base, hva_t hdm, hpa_t root_page_table, hpa_t eptp);
int nr_letters_equal(const char *str1, const char *str2);
int hamming_dist(u64 a, u64 b);
