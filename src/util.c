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
