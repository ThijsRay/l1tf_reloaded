#include "asm.h"
#include "flush_and_reload.h"
#include "constants.h"
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

int find_in_cache_threshold() {
  const size_t secret = 0xf7;

  const size_t nr_of_samples = 1000;

  const size_t reload_buffer_size = PAGE_SIZE * VALUES_IN_BYTE;
  uint8_t reload_buffer[reload_buffer_size];
  memset(&reload_buffer, 0, reload_buffer_size);

  size_t results[VALUES_IN_BYTE];

  for (size_t threshold = 30; threshold < 200; ++threshold) {
    memset(&results, 0, sizeof(size_t) * VALUES_IN_BYTE);

    for (size_t i = 0; i < nr_of_samples; ++i) {
      flush(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer);
      maccess(&reload_buffer[secret * PAGE_SIZE]);
      reload(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer, results, threshold);
    }
   
    // Only accept it as a good threshold if 90% is correct
    bool good_threshold = true;
    for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
      if (i != secret && results[i] > nr_of_samples * 0.1) {
        good_threshold = false;
        break;
      } else if (i == secret && results[i] < nr_of_samples * 0.9) {
        good_threshold = false;
      }
    }

    if (good_threshold) {
      return threshold;
    }
  }

  return -1;
}
