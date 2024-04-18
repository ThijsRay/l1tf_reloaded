#pragma once

#if __has_include(<stdint.h>)
#include "asm.h"
#include "constants.h"
#include <stdint.h>
#include <stdio.h>
#else
#include <linux/types.h>
#endif

#define deref_as_char_ptr(ptr) (*((volatile char *)(ptr)));
static inline __attribute__((always_inline)) void evict_l1d(const char *buf, const size_t set_index) {
  const size_t cache_line_size = 64;
  const size_t sets = 64;
  const size_t stride = cache_line_size * sets;
  const size_t ways = 16;

  for (size_t way = 0; way < ways; ++way) {
    size_t idx = (way * stride) + (set_index * cache_line_size);
    deref_as_char_ptr(&buf[idx]);
  }
  mfence();
}

static inline __attribute__((always_inline)) void evict_l2(const char *buf, const size_t set_index) {
  const size_t cache_line_size = 64;
  const size_t sets = 1024;
  const size_t stride = cache_line_size * sets;
  const size_t ways = 16;

  for (size_t way = 0; way < ways; ++way) {
    size_t idx = (way * stride) + (set_index * cache_line_size);
    deref_as_char_ptr(&buf[idx]);
  }
  mfence();
}
