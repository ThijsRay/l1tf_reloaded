#include "cache_eviction.h"
#include "asm.h"
#include "constants.h"
#include <err.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>

#define CACHE_EVICTION_BUFFER_SIZE (2)
static volatile uint8_t *cache_eviction_buffer[CACHE_EVICTION_BUFFER_SIZE];

void build_eviction_sets(void) {
  // Spawn the leak page
  for (size_t i = 0; i < CACHE_EVICTION_BUFFER_SIZE; ++i) {
    cache_eviction_buffer[i] = mmap(NULL, HUGE_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE, 0, 0);
    if (cache_eviction_buffer[i] == (void *)-1) {
      err(EXIT_FAILURE, "mmap failed of eviction set %ld", i);
    }

    for (size_t offset = 0; offset < HUGE_PAGE_SIZE;) {
      ssize_t read = getrandom((void *)cache_eviction_buffer[i], HUGE_PAGE_SIZE - offset, 0);
      if (read != -1) {
        offset += read;
      } else {
        err(EXIT_FAILURE, "failed to fill eviction buffer %ld with noise", i);
      }
    }
  }
}

void evict_l2(const size_t l2_set) {
  // assert(L2_SETS * L2_WAYS * CACHE_LINE_SIZE == HUGE_PAGE_SIZE);
  for (size_t sz = l2_set * CACHE_LINE_SIZE; sz < HUGE_PAGE_SIZE; sz += L2_SETS * CACHE_LINE_SIZE) {
    for (size_t i = 0; i < CACHE_EVICTION_BUFFER_SIZE; ++i) {
      cache_eviction_buffer[i][sz];
      lfence();
    }
  }
}

void free_eviction_sets(void) {
  for (size_t i = 0; i < CACHE_EVICTION_BUFFER_SIZE; ++i) {
    if (munmap((void *)cache_eviction_buffer[i], HUGE_PAGE_SIZE) != 0) {
      err(EXIT_FAILURE, "Failed to unmap cache eviction buffer %ld", i);
    }
  }
}
