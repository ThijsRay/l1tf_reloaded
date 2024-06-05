#include "msr.h"
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint64_t read_msr(size_t cpu, long msr_nr) {
  char path[128];
  snprintf(path, 128, "/dev/cpu/%lu/msr", cpu);
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    err(EXIT_FAILURE, "Failed to open file '%s'", path);
  }

  if (fseek(file, msr_nr, SEEK_SET) == -1) {
    err(EXIT_FAILURE, "Failed to seek to %lx in '%s'", msr_nr, path);
  };

  uint64_t data;
  if (fread(&data, sizeof(uint64_t), 1, file) != 1) {
    err(EXIT_FAILURE, "Failed to read MSR %lx from '%s'", msr_nr, path);
  }

  if (fclose(file) != 0) {
    err(EXIT_FAILURE, "Failed to close '%s'", path);
  };

  return data;
}
