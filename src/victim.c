// Adopted from https://github.com/gregvish/l1tf-poc
//
// MIT License
//
// Copyright (c) 2018 gregvish
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "asm.h"
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PAGE_SIZE (0x1000)

uint64_t virt_to_phys(volatile void *virtual_address) {
  int pagemap = 0;
  uint64_t value = 0;
  uint64_t page_frame_number = 0;

  pagemap = open("/proc/self/pagemap", O_RDONLY);
  if (pagemap < 0) {
    return 0;
  }

  if (sizeof(uint64_t) != pread(pagemap, &value, sizeof(uint64_t),
                                (((uint64_t)virtual_address) / PAGE_SIZE) * sizeof(uint64_t))) {
    return 0;
  }

  page_frame_number = value & ((1ULL << 54) - 1);
  if (page_frame_number == 0) {
    return 0;
  }

  return page_frame_number * PAGE_SIZE + (uint64_t)virtual_address % PAGE_SIZE;
}

volatile uint8_t test[] = {
    0xde, 0xad, 0xbe, 0xef, 0x67, 0x04, 0x3e, 0x1c, 0x2a, 0x2e, 0x4e, 0x86, 0x3d, 0x99, 0x3f, 0xac,
    0x1b, 0x8b, 0xce, 0xb6, 0x84, 0xf8, 0x2f, 0xf9, 0x95, 0x97, 0x08, 0x63, 0xc1, 0x1d, 0xf3, 0xee,
    0xab, 0xd7, 0xb3, 0x31, 0x20, 0x36, 0xa6, 0x38, 0xa2, 0x14, 0xb3, 0x2f, 0x8b, 0x0f, 0xc7, 0xfe,
    0x5c, 0xf8, 0x67, 0xb2, 0x74, 0x69, 0xb1, 0x4c, 0x33, 0xae, 0xe8, 0x4d, 0xba, 0xbe, 0xca, 0xfe,
    0x43, 0xa1, 0xdb, 0x8f, 0x1f, 0x53, 0xd9, 0x0c, 0xae, 0x4c, 0x40, 0x8d, 0x98, 0xdf, 0x36, 0x4e,
    0x34, 0x3f, 0x88, 0x84, 0xeb, 0x0c, 0x93, 0x51, 0xad, 0xb2, 0x83, 0x4e, 0x2b, 0xb6, 0x36, 0x94,
    0x3b, 0xd1, 0x05, 0xed, 0xdc, 0x31, 0xe9, 0x34, 0x62, 0xcc, 0xc3, 0xd4, 0x18, 0xb9, 0x0e, 0x06,
    0x39, 0xce, 0xb6, 0x07, 0x26, 0xd3, 0x62, 0x45, 0x51, 0xbd, 0x8f, 0x26, 0x85, 0x5c, 0x01, 0x91,
};

void dump_memory(volatile uint8_t *ptr, uint32_t size) {
  uint64_t i = 0;

  for (i = 0; i < size; i += 1) {
    if (i % 0x10 == 0 && i != 0) {
      printf("\n");
    }
    printf("%02x ", ptr[i]);
  }

  printf("\n");
}

int main(void) {
  char *buffer = aligned_alloc(PAGE_SIZE, sizeof(test));
  memcpy(buffer, (void *)test, sizeof(test));

  printf("Virt %p, Phys: 0x%lx\nData:\n", buffer, virt_to_phys(buffer));
  dump_memory((void *)buffer, sizeof(test));

  printf("clflushing the entire buffer...\n");
  for (size_t i = 0; i < sizeof(test); ++i) {
    clflush((void *)&test[i]);
  }

  printf("The data is still in memory, but not in cache. It will not be\n"
         "accessed anymore from now on. Going into an infinite loop...\n");

  while (1) {
    sched_yield();
  }

  return 0;
}
