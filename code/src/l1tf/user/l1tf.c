#include "../kernel/l1tf.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main() {
  int file = open("/proc/l1tf/scan_phys_mem", O_RDWR);

  char *needle = "\xde\xef";

  struct scan_phys_mem_params params;
  params.start_addr = 0;
  params.end_addr = (void *)0x1000000;
  params.stride = getpagesize();
  params.needle = needle;
  params.needle_length = 2;
  params.threshold = 150;

  assert(write(file, &params, sizeof(params)) == sizeof(params));

  return 0;
}
