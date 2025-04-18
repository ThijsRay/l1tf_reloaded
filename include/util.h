#pragma once
#include <stdio.h>
#include <stdarg.h>
#include "config.h"
#include "reverse.h"



#define CLEAR_LINE "\33[2K\r"
#define STR(a) STRSTR(a)
#define STRSTR(a) #a
#define dump(x) fprintf(stderr, "%30s = %16lx\n", STR(x), x)
#define dumpp(x) fprintf(stderr, "\t%30s = %16lx\n", STR(x), x)
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

#define for_each_around_range(name, center, start, end, step) \
        for (long name = (center), delta = (step); ((start) <= name && name < (end)) || ((start) <= (name+delta) && (name+delta) < (end)); name += delta, delta = -delta + (delta > 0 ? -(step) : (step))) \
                if ((start) <= name && name < (end))

#define HLINE "--------------------------------------------------------------------------------\n"
#define INDENT "    "

static inline __attribute__((always_inline)) u64 rdrand(void) {
	unsigned char success;
	u64 rand;
	do {
		asm volatile("rdrand %%rax; setc %1": "=a" (rand), "=qm"(success) ::);
	} while (!success);
	return rand;
}

#define LABEL_FB(name, maxtries, fallback) \
		static int global_count_##name = 0; \
		int nr_tries_##name = 0; \
	name: \
		if (++global_count_##name > 10000) \
			err(EXIT_FAILURE, "Saturation of global count of label '%s' in %s at %s:%d\n", STR(name), __func__, __FILE__, __LINE__); \
		if (++nr_tries_##name > maxtries) \
			fallback;

#define LABEL(name) LABEL_FB(name, 1000, err(EXIT_FAILURE, "Label tries outnumbered\n"));

void pr_dub(const char *format, ...);
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
int nr_letters_equal_len(const char *str1, const char *str2, int len);
int hamming_dist(u64 a, u64 b);
