#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../deps/PTEditor/ptedit_header.h"
#include "spectre_common.h"

bool is_equal(const char *restrict x, const char *restrict y, const size_t n) {
  bool equal = true;
  for (size_t i = 0; i < n; ++i) {
    equal &= x[i] == y[i];
  }
  return equal;
}

int main(int argc, char *argv[argc]) {
  fprintf(stderr, "Initializeing PTEdit...\r");
  assert(!ptedit_init());
  ptedit_use_implementation(PTEDIT_IMPL_USER);
  fprintf(stderr, "Initialized PTEdit!\n");

  const size_t MAX_PHYS_MEMORY = 17179869184;        // 16 GiB
  const int PAGE_SIZE = ptedit_get_pagesize() * 256; // HUGE PAGE!

  const size_t MAGIC_STR_LEN = strlen(MAGIC_STR);

  char *map = ptedit_pmap(0, MAX_PHYS_MEMORY);

  bool found = false;
  size_t found_pfn = 0;
  for (uintptr_t addr = 0; addr < MAX_PHYS_MEMORY; addr += PAGE_SIZE) {
    printf("\rReading addr %lx", addr);

    char *buffer = &map[addr];

    if (is_equal(buffer, MAGIC_STR, MAGIC_STR_LEN)) {
      found = true;
      found_pfn = ptedit_pte_get_pfn(buffer, 0);
      printf("\nFound at PTE %lx\n", found_pfn);
      break;
    }
  }

  if (!found) {
    printf("\nNot found :(\n");
    exit(1);
  }

  char new_page[4096] = {0};
  memcpy(new_page, OVERWRITTEN_STR, strlen(OVERWRITTEN_STR));

  ptedit_write_physical_page(found_pfn, new_page);
  return 0;
}
