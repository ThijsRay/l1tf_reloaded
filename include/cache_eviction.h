static inline __attribute__((always_inline)) void clflush(void *p) {
  asm volatile("clflush (%0)\n" ::"r"(p));
}
