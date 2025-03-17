#pragma once

#include <stddef.h>
#include <stdint.h>
#include "config.h"

uint64_t read_msr(size_t cpu, long msr_nr);
