#pragma once

#if __has_include(<stddef.h>)
#include <stddef.h>
#include <time.h>
#include "config.h"

static inline __attribute__((always_inline)) uint64_t clock_read(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1000000000 + ts.tv_nsec;
}
#else
#include <linux/types.h>
#endif

// From figure 4 of Yarom and Falkner, “FLUSH+RELOAD: A High Resolution, Low Noise,
// L3 Cache Side-Channel Attack.”
static inline __attribute__((always_inline)) size_t access_time(void *ptr) {
  volatile unsigned long time;

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

      "movl %%eax, %%esi\n"
      "movl (%1), %%eax\n"

      "lfence\n"
      "rdtsc\n"
      "subl %%esi, %%eax\n"
      : "=a"(time)
      : "c"(ptr)
      : "%esi", "%edx");
  return time;
}
