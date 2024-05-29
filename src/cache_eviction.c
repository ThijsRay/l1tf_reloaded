#include "cache_eviction.h"
#include "plumtree.h"
#include <err.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *plumtree_thread_entry(void *data) {
  struct plumtree_pthread_params *x = data;
  x->ret = plumtree_main(x->option);
  return data;
}

struct eviction_sets parse_eviction_sets(const struct plumtree_pthread_params *const data) {
  struct eviction_sets ev = {0};

  printf("%s\n", data->ret.sets);
  const char delimiters[] = " :)\n";
  char *token, *cp, *save_ptr = NULL;
  cp = strdup(data->ret.sets);

  // Get the first token
  token = strtok_r(cp, delimiters, &save_ptr);
  do {
    // Parse the eviction set number
    if (!strcmp(token, "Eviction")) {
      token = strtok_r(NULL, delimiters, &save_ptr);
      if (token != NULL && !strcmp(token, "set")) {
        token = strtok_r(NULL, delimiters, &save_ptr);

        char *tail;
        long int evset_nr = strtol(token, &tail, 10);
        // Conversion happened!
        if (tail != token) {
          printf("%ld\n", evset_nr);
          continue;
        }
      }
      errx(EXIT_FAILURE, "Malformed set message");
    }
    // printf("%s\n", token);
  } while (token = strtok_r(NULL, delimiters, &save_ptr), token != NULL);

  free(cp);
  return ev;
}

void build_eviction_sets(void) {
  pthread_t thread;
  pthread_attr_t attr;
  struct plumtree_pthread_params *status = NULL;

  do {
    if (pthread_attr_init(&attr) != 0) {
      err(EXIT_FAILURE, "Failed to initialize phtread attributes");
    }

    struct plumtree_pthread_params params = {.option = 2};
    if (pthread_create(&thread, &attr, &plumtree_thread_entry, &params) != 0) {
      err(EXIT_FAILURE, "Failed to create phtread");
    }

    int rc;
    pthread_attr_destroy(&attr);
    if (rc = pthread_join(thread, (void **)&status), rc != 0) {
      err(EXIT_FAILURE, "plumtree did not succeed: error code %d", rc);
    }

    if (status == NULL) {
      err(EXIT_FAILURE, "Status should never be NULL");
    }

    if (status->ret.sets == NULL || status->ret.to_be_freed == NULL) {
      continue;
    }

    // TODO: parse the eviction sets
    // If not enough, free everything and try again
    parse_eviction_sets(status);

  } while (status == NULL);

  printf("%s\n", (char *)status);
}

void free_eviction_sets(struct eviction_sets sets) {
  for (size_t set_idx = 0; set_idx < sets.len; ++set_idx) {
    struct eviction_set set = sets.sets[set_idx];
    free(set.ptrs);
  }
  free(sets.sets);
}
