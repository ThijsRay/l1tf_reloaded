#include <stdint.h>
#include <stddef.h>

size_t measure_in_cache_threshold_time(volatile uint8_t *ptr);
void flush(size_t nr_values, size_t stride, uint8_t buffer[nr_values * stride]);
