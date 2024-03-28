#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "hypercall.h"

void hypercall(struct hypercall_opts *opts) {
  int fd = open("/proc/ipi_hypercall", O_WRONLY);
  if (fd < 0) {
    err(fd, "Failed to open /proc/ipi_hypercall");
  }

  int b = write(fd, opts, sizeof(*opts));
  close(fd);
  if (b < 0) {
    err(errno, "Failed to write to /proc/ipi_hypercall");
  } else {
    printf("Succesfully wrote %d/%ld bytes\n", b, sizeof(*opts));
  }
}

int main(int argc, char *argv[argc]) {
  struct hypercall_opts opts = {0};
  memset(&opts, 0xff, sizeof(opts));
  hypercall(&opts);

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
