#pragma once

#include <stdint.h>
static inline __attribute__((always_inline)) void clflush(void *p) {
  __asm__ volatile("clflush (%0)\n" ::"r"(p));
}

static inline __attribute__((always_inline)) uint64_t rdtsc(void) {
  uint64_t lo, hi;
  __asm__ volatile("rdtsc\n" : "=a"(lo), "=d"(hi)::"rcx");
  return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) void lfence(void) { __asm__ volatile("lfence\n"); }

static inline __attribute__((always_inline)) void mfence(void) { __asm__ volatile("mfence\n"); }

static inline __attribute__((always_inline)) void maccess(void *ptr) {
  __asm__ volatile("movq (%0), %%rax\n" : : "r"(ptr) : "rax");
}

static inline void cpuid(int code, uint32_t *a, uint32_t *d) {
  __asm__ volatile("cpuid" : "=a"(*a), "=d"(*d) : "0"(code) : "ebx", "ecx");
}
