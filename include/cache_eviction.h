#pragma once

#if __has_include(<stdint.h>)
#include <stdint.h>
#else
#include <linux/types.h>
#endif

#define deref_as_char_ptr(ptr) (*((volatile char *)(ptr)));
static inline __attribute__((always_inline)) void evict_set_l1d(const char *buf, int set_index) {
  uintptr_t addr = (uintptr_t)buf;

  // Change the set index bits in the address
  set_index &= 0b111111;
  uintptr_t set_mask = ~((0b111111) << 6);
  addr = (addr & set_mask) | (set_index << 6);

  // Since there are 8 ways in L1d, we need access the same set with 8 different tags.
  // This can be done by changing some bits of the tag, while skipping the 6 offset bits
  // and the 6 set index bits.
  deref_as_char_ptr(addr);
  deref_as_char_ptr(addr ^ (1 << 12));
  deref_as_char_ptr(addr ^ (2 << 12));
  deref_as_char_ptr(addr ^ (3 << 12));
  deref_as_char_ptr(addr ^ (4 << 12));
  deref_as_char_ptr(addr ^ (5 << 12));
  deref_as_char_ptr(addr ^ (6 << 12));
  deref_as_char_ptr(addr ^ (7 << 12));
}
