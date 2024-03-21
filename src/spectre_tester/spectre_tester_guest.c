#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../hypercall/hypercall.h"

int write_to_ipi_proc(struct hypercall_opts opts) {
  int fd = open("/proc/ipi_hypercall", O_WRONLY);
  if (fd < 0) {
    err(fd, "Failed to open /proc/ipi_hypercall");
  }

  int b = write(fd, &opts, sizeof(opts));
  if (b < 0) {
    errno = b;
    err(b, "Failed to write to /proc/ipi_hypercall");
  }
  printf("Send IPI to %d CPUs\n", b);
  return b;
}

int main(int argc, char *argv[argc]) {
  const size_t PAGE_SIZE = getpagesize();
  void *buffer = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
  if (!buffer) {
    err(errno, "Failed to allocate spectre buffer");
  }
  memset(buffer, 0, PAGE_SIZE);

  char *MAGIC_STR = "This is the MAGIC string of the spectre buffer! "
                    "0x8aafda87bb56a3b0ac462b7cd615a72e";
  memcpy(buffer, MAGIC_STR, strnlen(MAGIC_STR, PAGE_SIZE));

  char chr = 0;
  do {
    printf("Scan memory from the hypervisor now! Is it done? [y/N]\n");
  } while (chr = getchar(), chr != 'Y' && chr != 'y');

  struct hypercall_opts opts = {
      .mask_low = 0xffffffff, .mask_high = 0xffffffff, .min = 0, .icr = 0};
  write_to_ipi_proc(opts);

  free(buffer);
}
