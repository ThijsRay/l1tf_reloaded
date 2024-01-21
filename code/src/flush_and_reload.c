#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "asm.h"
#include "statistics.h"

size_t access_time(void* ptr) {
  // From x86 docs
  // If software requires RDTSC to be executed only after all previous
  // instructions have executed and all previous loads and stores are
  // globally visible, it can execute the sequence MFENCE;LFENCE
  // immediately before RDTSC.
  mfence();
  lfence();
  size_t start = rdtsc();
  // From x86 docs
  // If software requires RDTSC to be executed prior to execution of any
  // subsequent instruction (including any memory accesses), it can execute
  // the sequence LFENCE immediately after RDTSC.
  lfence();

  maccess(ptr);

  mfence();
  lfence();
  size_t end = rdtsc();
  lfence();

  return end - start;
}

size_t measure_in_cache_threshold_time(void *ptr) {
  size_t nr_of_measurements = 100000;

  size_t* in_cache_times = malloc(sizeof(size_t) * nr_of_measurements);
  size_t* not_in_cache_times = malloc(sizeof(size_t) * nr_of_measurements);

  assert(in_cache_times);
  assert(not_in_cache_times);

  for (size_t i = 0; i < nr_of_measurements; ++i) {
    // Not in cache
    clflush(ptr);
    not_in_cache_times[i] = access_time(ptr);

    // In cache
    in_cache_times[i] = access_time(ptr);
  }

  const size_t threshold = threshold_with_least_error(nr_of_measurements, in_cache_times, not_in_cache_times);

  free(in_cache_times);
  free(not_in_cache_times);

  return threshold;
}

void flush(size_t nr_values, size_t stride, uint8_t buffer[nr_values * stride]) {
  for (size_t n = 0; n < nr_values; ++n) {
    clflush(&buffer[n * stride]);
  }
  mfence();
}
