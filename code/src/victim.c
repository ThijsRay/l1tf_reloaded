#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void move_to_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  int affinity = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
  assert(!affinity);
}

void usage(char* program_name) {
    fprintf(stderr, "Usage: %s [cpu] [secret in hex, max 64 bits]\n", program_name);
    exit(1);
}

int main(int argc, char *argv[argc]) {
  assert(argc > 0);
  if (argc != 3) {
    usage(argv[0]);
  }

  // Parsing CPU id
  char* tailptr = NULL;
  int cpu = strtoul(argv[1], &tailptr, 10);
  if (tailptr == argv[1]) {
    usage(argv[0]);
  }
  assert(tailptr != argv[1]);

  // Parsing secret
  tailptr = NULL;
  uint64_t secret = strtoull(argv[2], &tailptr, 16);
  if (tailptr == argv[2]) {
    usage(argv[0]);
  }
  assert(tailptr != argv[2]);

  printf("Setting affinity to be scheduled to CPU core %d\n", cpu);
  move_to_cpu(cpu);

  printf("Writing the secret 0x%lx to RSP\n", secret);
  while (1) {
			asm volatile(
				"movq %0, (%%rsp)\n"
				"mfence\n"
				::"r"(secret));
	}
}
