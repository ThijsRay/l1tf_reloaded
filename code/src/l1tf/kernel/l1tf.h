#pragma once
#include <linux/types.h>

struct scan_phys_mem_params {
  void *start_addr;
  void *end_addr;
  size_t stride;
  char *needle;
  size_t needle_length;
  size_t threshold;
};
