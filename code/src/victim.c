#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pagemap.h"

void move_to_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  int affinity = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
  assert(!affinity);
}

void usage(char *program_name) {
  fprintf(stderr, "Usage: %s [cpu]\n", program_name);
  exit(1);
}

int main(int argc, char *argv[argc]) {
  assert(argc > 0);
  if (argc != 2) {
    usage(argv[0]);
  }

  // Parsing CPU id
  char *tailptr = NULL;
  int cpu = strtoul(argv[1], &tailptr, 10);
  if (tailptr == argv[1]) {
    usage(argv[0]);
  }
  assert(tailptr != argv[1]);

  printf("Setting affinity to be scheduled to CPU core %d\n", cpu);
  move_to_cpu(cpu);

  char *buffer = aligned_alloc(getpagesize(), getpagesize());
  memset(buffer, 0, getpagesize());

  char secret_str[64] =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0";

  uintptr_t dst_addr = get_pagemap_entry(getpid(), buffer).pfn;
  printf("dest buffer pfn:\t0x%lx\n", dst_addr);
  uintptr_t src_addr = get_pagemap_entry(getpid(), secret_str).pfn;
  printf("src buffer pfn:\t0x%lx\n", src_addr);

  printf("Accessing the secret at %p (pfn: 0x%lx)\n", buffer, dst_addr);
  while (true) {
    memcpy(buffer, secret_str, 64);
    asm volatile("verw");
  }
}
