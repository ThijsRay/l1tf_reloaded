#include "flush_and_reload.h"
#include "asm.h"
#include "statistics.h"
#include <assert.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

size_t measure_in_cache_threshold_time(void *ptr) {
  size_t n = 100000;

  size_t *in_cache_times = malloc(sizeof(size_t) * n);
  assert(in_cache_times);

  size_t in_cache_variance = 0;
  do {
    flush(n, sizeof(size_t), (uint8_t *)in_cache_times);
    for (size_t i = 0; i < n; ++i) {
      // In cache
      maccess(ptr);
      in_cache_times[i] = access_time(ptr);
    }

    in_cache_variance = variance(n, in_cache_times);
    fprintf(stderr, "Variance: %ld\n", in_cache_variance);
    sched_yield();
  } while (in_cache_variance > 200);

  const size_t threshold = mean(n, in_cache_times);
  free(in_cache_times);

  return threshold;
}
