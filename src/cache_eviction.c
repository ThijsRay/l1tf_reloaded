#include "cache_eviction.h"
#include "plumtree.h"
#include <err.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void *plumtree_thread_entry(void *d) {
  int *arg = (int *)d;
  return plumtree_main(*arg);
}

struct eviction_sets parse_eviction_sets(char const *const data) {
  struct eviction_sets ev = {0};
  return ev;
}

void build_eviction_sets(void) {
  pthread_t thread;
  pthread_attr_t attr;
  char *status = NULL;

  do {
    if (pthread_attr_init(&attr) != 0) {
      err(EXIT_FAILURE, "Failed to initialize phtread attributes");
    }

    int option = 2;
    if (pthread_create(&thread, &attr, &plumtree_thread_entry, &option) != 0) {
      err(EXIT_FAILURE, "Failed to create phtread");
    }

    int rc;
    pthread_attr_destroy(&attr);
    if (rc = pthread_join(thread, (void **)&status), rc != 0) {
      err(EXIT_FAILURE, "plumtree did not succeed: error code %d", rc);
    }

    if (status == NULL) {
      continue;
    }

    parse_eviction_sets(status);

  } while (status == NULL);

  printf("%s\n", (char *)status);
}

void free_eviction_sets(struct eviction_sets sets) {
  for (size_t set_idx = 0; set_idx < sets.len; ++set_idx) {
    struct eviction_set *set = sets.sets[set_idx];
    free(set->ptrs);
  }
  free(sets.sets);
}
