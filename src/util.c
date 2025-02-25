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
