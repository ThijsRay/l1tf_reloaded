#pragma once

#include <linux/types.h>

struct hypercall_opts {
  unsigned long mask_low;
  unsigned long mask_high;
  unsigned long icr;
  uint32_t min;
};
