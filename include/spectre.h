#pragma once
#include <stdint.h>
#include "hypercall.h"

void half_spectre(unsigned char *p, uintptr_t pa_p, uintptr_t pa_base);

