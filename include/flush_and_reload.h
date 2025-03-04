#pragma once

#include "asm.h"
#include "constants.h"
#include "timing.h"
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

size_t measure_in_cache_threshold_time(void *ptr);
static inline __attribute__((always_inline)) void flush(const size_t nr_values,
                                                        uint8_t buffer[nr_values * STRIDE]) {
  for (size_t n = 0; n < nr_values; ++n) {
    clflush(&buffer[n * STRIDE]);
  }
}

static inline __attribute__((always_inline)) ssize_t reload(const size_t nr_values,
                                                            const uint8_t buffer[nr_values * STRIDE],
                                                            const size_t threshold) {
  for (size_t i = 0; i < nr_values; ++i) {
    size_t time = access_time((void *)&buffer[i * STRIDE]);
    if (time < threshold) {
      return i;
    }
  }
  return -1;
}
