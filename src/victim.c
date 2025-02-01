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
#include "secret.h"
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

volatile uint8_t test[sizeof(SECRET_DATA)] = {0};

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
  memcpy(buffer, (void *)SECRET_DATA, sizeof(test));

  uintptr_t phys_addr = virt_to_phys(buffer);
  if (phys_addr != 0) {
    printf("Phys: 0x%lx\n", virt_to_phys(buffer));
  }

  printf("Data:\n");
  dump_memory((void *)buffer, sizeof(test));

  printf("clflushing the entire buffer...\n");
  for (size_t i = 0; i < sizeof(test); ++i) {
    clflush((void *)&test[i]);
    clflush((void *)&buffer[i]);
  }

  printf("The data is still in memory, but not in cache. It will not be\n"
         "accessed anymore from now on. Going into an infinite loop...\n");

  while (1) {
    sched_yield();
  }

  return 0;
}
