#pragma once
#include <stdlib.h>

struct eviction_set {
  size_t len;
  void *ptrs[];
};

struct eviction_sets {
  size_t len;
  struct eviction_set *sets[];
} __attribute__((deallocated_by(free_eviction_sets)));

void build_eviction_sets(void);
void free_eviction_sets(struct eviction_sets);
