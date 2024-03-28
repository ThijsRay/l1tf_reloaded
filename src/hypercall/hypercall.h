#pragma once

#if __has_include(<stdint.h>)
#include <stdint.h>
#else
#include <linux/types.h>
#endif

struct hypercall_opts {
  unsigned long mask_low;
  unsigned long mask_high;
  unsigned long icr;
  uint32_t min;
};
