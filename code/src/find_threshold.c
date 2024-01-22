#include "asm.h"
#include "flush_and_reload.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

int find_in_cache_threshold() {
  const size_t PAGE_SIZE = 4096;
  const size_t NR_OF_VALUES = 256;
  const size_t secret = 0xf7;

  const size_t nr_of_samples = 1000;

  const size_t reload_buffer_size = PAGE_SIZE * NR_OF_VALUES;
  uint8_t reload_buffer[reload_buffer_size];
  memset(&reload_buffer, 0, reload_buffer_size);

  size_t results[NR_OF_VALUES];

  for (size_t threshold = 30; threshold < 200; ++threshold) {
    memset(&results, 0, sizeof(size_t) * NR_OF_VALUES);

    for (size_t i = 0; i < nr_of_samples; ++i) {
      flush(NR_OF_VALUES, PAGE_SIZE, reload_buffer);
      maccess(&reload_buffer[secret * PAGE_SIZE]);
      reload(NR_OF_VALUES, PAGE_SIZE, reload_buffer, results, threshold);
    }
   
    // Only accept it as a good threshold if 95% is correct
    bool good_threshold = true;
    for (size_t i = 0; i < NR_OF_VALUES; ++i) {
      if (i != secret && results[i] > nr_of_samples * 0.05) {
        good_threshold = false;
        break;
      } else if (i == secret && results[i] < nr_of_samples * 0.95) {
        good_threshold = false;
      }
    }

    if (good_threshold) {
      return threshold;
    }
  }

  return -1;
}
