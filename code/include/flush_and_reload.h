#pragma once

#include <stdint.h>
#include <stddef.h>
#include "asm.h"

static inline __attribute__((always_inline)) size_t access_time(void* ptr) {
  size_t start, end;
  asm volatile(
    // From x86 docs
    // If software requires RDTSC to be executed only after all previous
    // instructions have executed and all previous loads and stores are
    // globally visible, it can execute the sequence MFENCE;LFENCE
    // immediately before RDTSC.
    "mfence\n"
    "lfence\n"
    "rdtsc\n"
    // From x86 docs
    // If software requires RDTSC to be executed prior to execution of any
    // subsequent instruction (including any memory accesses), it can execute
    // the sequence LFENCE immediately after RDTSC.
    "lfence\n"
    "movq %%rax, %[start]\n"
    "movq (%[ptr]), %%rax\n"
    "mfence\n"
    "lfence\n"
    "rdtsc\n"
    "lfence\n"
    "movq %%rax, %[end]\n"
    : [start] "=r" (start), [end] "=r" (end) : [ptr] "r" (ptr) : "rax", "rdx"
  );
  return end - start;
}

size_t measure_in_cache_threshold_time(void *ptr);
void flush(size_t nr_values, size_t stride, uint8_t buffer[nr_values * stride]);

static inline __attribute__((always_inline)) void reload(const size_t nr_values,
            const size_t stride,
            const uint8_t buffer[nr_values * stride],
            size_t results[nr_values],
            const size_t threshold) {
  for (size_t i = 0; i < nr_values; i++) {
    size_t time = access_time((void*)&buffer[i * stride]); 
    if (time < threshold) {
      results[i] += 1;
    }
  }
}
