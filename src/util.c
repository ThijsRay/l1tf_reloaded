#define _XOPEN_SOURCE 600
#define _GNU_SOURCE
#include <time.h>
#include <sched.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/vfs.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "util.h"
#include "leak.h"

void set_cpu_affinity(int cpu_id) {
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu_id, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0) {
		err(EXIT_FAILURE, "Error setting CPU affinity of process with PID %d to %d: %s\n",
				getpid(), cpu_id, strerror(errno));
	}
}

int get_sibling(int cpu_id)
{
        int brother, sister;
        char fname[64];
        snprintf(fname, 64, "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu_id);
        FILE *f = fopen(fname, "r");
        if (!f) {
                perror("could not open sysfs thread_siblings_list file");
                exit(EXIT_FAILURE);
        }
        assert(fscanf(f, "%d", &brother) == 1);
	fgetc(f);
        assert(fscanf(f, "%d", &sister) == 1);
        fclose(f);
        if (brother == cpu_id)
                return sister;
        if (sister == cpu_id)
                return brother;
        err(EXIT_FAILURE, "Could not find cpu id %d in file %s\n", cpu_id, fname);
}


uint64_t file_read_lx(const char *filename)
{
    char buf[32];
    int fd = open(filename, O_RDONLY); if (fd < 0) { printf("error open %s", filename); exit(1); }
    int rv = read(fd, buf, 32);  if (rv < 0) { printf("error read %s", filename); exit(1); }
    int cv = close(fd); if (cv < 0) { printf("error close %s", filename); exit(1); }
    return strtoull(buf, NULL, 16);
}

uint64_t file_write_lx(const char *filename, uint64_t uaddr)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lx\n", uaddr);
    int fd = open(filename, O_WRONLY); if (fd < 0) { printf("error open %s", filename); exit(1); }
    u64 rv = write(fd, buf, 32);
    int cv = close(fd); if (cv < 0) { printf("error close %s", filename); exit(1); }
    return rv;
}

uintptr_t procfs_direct_map(void)
{
    return file_read_lx("/proc/preload_time/direct_map");
}

uintptr_t procfs_pgd(void)
{
    return file_read_lx("/proc/preload_time/pgd");
}

uintptr_t procfs_get_physaddr(gva_t uaddr)
{
    file_write_lx("/proc/preload_time/phys_addr", uaddr);
    return file_read_lx("/proc/preload_time/phys_addr");
}

u64 procfs_get_data(gva_t addr)
{
    return file_write_lx("/proc/preload_time/data", addr);
}

void print_page_table(hpa_t base, hpa_t page_table)
{
    char data[0x1000];
    leak(data, base, page_table, 0x1000);
    for (pte_t *pte = (pte_t *)data; (u64)pte < (u64)data+0x1000; pte++)
        if (*pte & 1)
            printf("[%4lx] --> %16lx\n", pte-(u64 *)data, *pte);
}

void print_region(va_t start, va_t end)
{
    long si = BITS(start, 48, 39);
    long sj = BITS(start, 39, 30);
    long sk = BITS(start, 30, 21);
    long sl = BITS(start, 21, 12);
    long ei = BITS(end, 48, 39);
    long ej = BITS(end, 39, 30);
    long ek = BITS(end, 30, 21);
    long el = BITS(end, 21, 12);
    printf("[%16lx, %16lx) [%3lx/%3lx/%3lx/%3lx, %3lx/%3lx/%3lx/%3lx)\n",
            start, end, si, sj, sk, sl, ei, ej, ek, el);
}

void dump_page_table_mappings(hpa_t base, hpa_t root_page_table, hpa_t eptp)
{
    const int verbose = 0;
    pte_t pgd[0x200];
    pte_t pud[0x200];
    pte_t pmd[0x200];
    pte_t pte[0x200];
    hpa_t next_page_table;
    va_t start = -1, end = -1;
    leak(&pgd, base, root_page_table, 0x1000);
    for (long i = 0x1ff; i < 0x200; i++) {
        if (!(pgd[i] & 1))
            continue;
        next_page_table = pgd[i] & PFN_MASK;
        if (eptp) next_page_table = translate(base, next_page_table, eptp) & PFN_MASK;
        leak(&pud, base, next_page_table, 0x1000);
        for (long j = 0x100; j < 0x200; j++) {
            if (!(pud[j] & 1)) {
                if (start != -1ULL)
                    print_region(start, end);
                start = -1ULL;
                continue;
            }
            if (IS_HUGE(pud[j])) {
                va_t va = ((i & 0x100) ? (0xffffULL << 48) : 0) | (i << 39) | (j << 30);
                if (verbose) { printf("pgd[%3lx] pud[%3lx] (1GB) ", i, j); print_region(va, va + (1UL << 30)); }
                if (start == -1ULL || va != end) {
                    if (start != -1ULL)
                        print_region(start, end);
                    start = va;
                }
                end = va + (1UL << 30);
                continue;
            }
            next_page_table = pud[j] & PFN_MASK;
            if (eptp) next_page_table = translate(base, next_page_table, eptp) & PFN_MASK;
            leak(&pmd, base, next_page_table, 0x1000);
            for (long k = 0; k < 0x200; k++) {
                if (!(pmd[k] & 1)) {
                    if (start != -1ULL)
                        print_region(start, end);
                    start = -1ULL;
                    continue;
                }
                if (IS_HUGE(pmd[k])) {
                    va_t va = ((i & 0x100) ? (0xffffULL << 48) : 0) | (i << 39) | (j << 30) | (k << 21);
                    if (verbose) { printf("pgd[%3lx] pud[%3lx] pmd[%3lx] (2MB) ", i, j, k); print_region(va, va + (1UL << 21)); }
                    if (start == -1ULL || va != end) {
                        if (start != -1ULL)
                            print_region(start, end);
                        start = va;
                    }
                    end = va + (1UL << 21);
                    continue;
                }
                next_page_table = pmd[k] & PFN_MASK;
                if (eptp) next_page_table = translate(base, next_page_table, eptp) & PFN_MASK;
                leak(&pte, base, next_page_table, 0x1000);
                for (long l = 0; l < 0x200; l++) {
                    if (!(pte[l] & 1)) {
                        if (start != -1ULL)
                            print_region(start, end);
                        start = -1ULL;
                        continue;
                    }
                    va_t va = ((i & 0x100) ? (0xffffULL << 48) : 0) | (i << 39) | (j << 30) | (k << 21) | (l << 12);
                    if (verbose) { printf("pgd[%3lx] pud[%3lx] pmd[%3lx] pte[%3lx] ", i, j, k, l); print_region(va, va + (1UL << 12)); }
                    if (start == -1ULL || va != end) {
                        if (start != -1ULL)
                            print_region(start, end);
                        start = va;
                    }
                    end = va + (1UL << 12);
                }
            }
        }
    }
    if (start != -1ULL)
        print_region(start, end);
}
