#pragma once
#include <stdint.h>
#include "hypercall.h"

void test_half_spectre(unsigned char *p, uintptr_t pa_p, uintptr_t pa_base);
uintptr_t spectre_find_base(char *p, uintptr_t pa_p);
void spectre_touch_base_start(void);
void spectre_touch_base_stop(void);
void half_spectre_start(uintptr_t base, uintptr_t pa);
void half_spectre_stop(void);
