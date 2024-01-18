#include <stdint.h>
#include <stddef.h>

void flush(size_t nr_values, size_t stride, uint8_t buffer[nr_values * stride]);
