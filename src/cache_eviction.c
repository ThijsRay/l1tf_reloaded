#include "cache_eviction.h"
#include "asm.h"
#include "constants.h"
#include "plumtree.h"
#include <assert.h>
#include <err.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
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
  const size_t nr_of_sets = 4096;

  ev.sets = calloc(nr_of_sets, sizeof(struct eviction_set));
  if (ev.sets == NULL) {
    err(EXIT_FAILURE, "Failed to allocate space for eviction sets");
  }

  const char delimiters[] = " :)\n";
  char *token, *cp, *save_ptr = NULL;
  cp = strdup(data->ret.sets);

  size_t evset_nr = -1;
  // Get the first token
  token = strtok_r(cp, delimiters, &save_ptr);
  do {
    // Parse the eviction set number
    if (!strcmp(token, "Eviction")) {
      token = strtok_r(NULL, delimiters, &save_ptr);
      if (token != NULL && !strcmp(token, "set")) {
        token = strtok_r(NULL, delimiters, &save_ptr);

        char *tail;
        evset_nr = strtol(token, &tail, 10);
        // Conversion happened!
        if (tail != token) {
          if (evset_nr == ev.len) {
            ev.len += 1;
            ev.sets[evset_nr].len = 0;
            // max number of pointers in each eviction set
            ev.sets[evset_nr].ptrs = calloc(32, sizeof(void *));
          }
          continue;
        }
      }
      errx(EXIT_FAILURE, "Malformed set message");
    }

    if (!strcmp(token, "Add")) {
      token = strtok_r(NULL, delimiters, &save_ptr);
      if (token != NULL) {
        char *tail;
        uintptr_t addr = strtol(token, &tail, 16);
        // Conversion succesful!
        if (tail != token) {
          struct eviction_set *evs = &ev.sets[evset_nr];
          evs->ptrs[evs->len] = (void *)addr;
          evs->len += 1;
          continue;
        }
      }
      errx(EXIT_FAILURE, "Malformed address");
    }
  } while (token = strtok_r(NULL, delimiters, &save_ptr), token != NULL);

  if (ev.len != ((nr_of_sets / 64))) {
    errx(EXIT_FAILURE, "Failed to find all eviction sets");
  }

  free(cp);
  return ev;
}

void extend_page_head_eviction_sets(struct eviction_sets *ev) {
  size_t original_length = ev->len;
  for (size_t x = 0; x < original_length; ++x) {
    const struct eviction_set original_set = ev->sets[x];

    for (size_t offset = CACHE_LINE_SIZE; offset < PAGE_SIZE; offset += CACHE_LINE_SIZE) {
      struct eviction_set *new_set = &ev->sets[ev->len];
      new_set->len = original_set.len;
      new_set->ptrs = calloc(new_set->len, sizeof(void *));
      for (size_t i = 0; i < new_set->len; ++i) {
        new_set->ptrs[i] = (char *)original_set.ptrs[i] + offset;
      }
      ev->len += 1;
    }
  }
}

struct eviction_sets build_eviction_sets(void) {
  pthread_t thread;
  pthread_attr_t attr;
  struct plumtree_pthread_params *status = NULL;
  struct eviction_sets ev = {0};

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

    ev = parse_eviction_sets(status);
    extend_page_head_eviction_sets(&ev);

  } while (status == NULL);
  return ev;
}

void evict_set(const struct eviction_sets *const sets, const size_t set_idx) {
  assert(set_idx < sets->len);
  const struct eviction_set ev = sets->sets[set_idx];
  for (size_t i = 0; i < ev.len; ++i) {
    maccess(ev.ptrs[i]);
  }
}

void free_eviction_sets(struct eviction_sets sets) {
  for (size_t set_idx = 0; set_idx < sets.len; ++set_idx) {
    struct eviction_set set = sets.sets[set_idx];
    free(set.ptrs);
  }
  free(sets.sets);
}
