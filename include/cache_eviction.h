#pragma once
#include "plumtree.h"

struct eviction_set {
  size_t len;
  void **ptrs;
};

struct eviction_sets {
  size_t len;
  struct eviction_set *sets;
};

struct plumtree_pthread_params {
  int option;
  struct PlumtreeReturn ret;
};

struct eviction_sets build_eviction_sets(void);
void evict_set(const struct eviction_sets *const sets, const size_t set_idx);
void free_eviction_sets(struct eviction_sets);
