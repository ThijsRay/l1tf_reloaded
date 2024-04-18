#include "cache_eviction.h"
#include "constants.h"
#include "timing.h"
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int main() {
  void *huge_page = mmap(NULL, HUGE_PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE, 0, 0);
  if (huge_page == (void *)-1) {
    err(errno, "mmap failed (do 'echo 1 | sudo tee /proc/sys/vm/nr_hugepages' first)");
  }
  printf("Addr is %p\n", huge_page);

  char *variable = malloc(64);
  assert(variable);

  const size_t iters = 10000;

  for (size_t set_idx = 0; set_idx < 1024; ++set_idx) {
    size_t before = -1;
    size_t after = -1;
    for (size_t i = 0; i < iters; ++i) {
      size_t before_time = access_time(variable);
      evict_l1d(huge_page, set_idx);
      evict_l2(huge_page, set_idx);
      size_t after_time = access_time(variable);

      before = before_time < before ? before_time : before;
      after = after_time < after ? after_time : after;
    }
    if (after > before) {
      printf("%ld\tBefore: %ld\tAfter: %ld\n", set_idx, before, after);
    }
  }

  free(variable);
  munmap(huge_page, HUGE_PAGE_SIZE);
}
