#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void move_to_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  int affinity = sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
  assert(!affinity);
}

void usage(char *program_name) {
  fprintf(stderr, "Usage: %s [cpu] [secret character in hex]\n", program_name);
  exit(1);
}

int main(int argc, char *argv[argc]) {
  assert(argc > 0);
  if (argc != 3) {
    usage(argv[0]);
  }

  // Parsing CPU id
  char *tailptr = NULL;
  int cpu = strtoul(argv[1], &tailptr, 10);
  if (tailptr == argv[1]) {
    usage(argv[0]);
  }
  assert(tailptr != argv[1]);

  // Parsing secret
  tailptr = NULL;
  uint8_t secret = strtoul(argv[2], &tailptr, 16) & 0xff;
  if (tailptr == argv[2]) {
    usage(argv[0]);
  }
  assert(tailptr != argv[2]);

  printf("Setting affinity to be scheduled to CPU core %d\n", cpu);
  move_to_cpu(cpu);

  char buffer[4096] = {0};
  char secret_str[8] = "SECRET0\0";
  secret_str[6] = cpu + 1;
  printf("Writing the secret 0x%lx to buffer\n", *(uint64_t *)secret_str);
  while (1) {
    memcpy(buffer, secret_str, 8);
  }
}
