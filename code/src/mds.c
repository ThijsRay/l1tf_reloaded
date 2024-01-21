#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "flush_and_reload.h"

int main() {
  const size_t PAGE_SIZE = getpagesize();
  const size_t NR_VALUES = 256;
  uint8_t buffer[NR_VALUES * PAGE_SIZE];

  void* new_addr = mmap(NULL,
                        PAGE_SIZE * NR_VALUES,
                        PROT_READ,
                        MAP_PRIVATE | MAP_ANONYMOUS,
                        -1,
                        0);

  while (1) {
    size_t time = measure_in_cache_threshold_time(new_addr);
  }

  // for (int i = 0; i < 10; ++i) {
  //   printf("%p\n", new_addr);
  //   munmap(new_addr, PAGE_SIZE * NR_VALUES);
  // }
  // flush(NR_VALUES, PAGE_SIZE, buffer);

  // printf("Hello!\n");
  return 0;
}
