#include <stddef.h>
#include <stdint.h>
#include "flush_and_reload.h"

int main() {
  const size_t STRIDE = 4096;
  const size_t NR_VALUES = 256;
  uint8_t buffer[STRIDE * NR_VALUES];

  flush(NR_VALUES, STRIDE, buffer);
  return 0;
}
