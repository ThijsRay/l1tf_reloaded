#pragma once
#include "config.h"
#include "reverse.h"
#include "util.h"
#include "helpers.h"

#define BITS_MASK(n, m) ( ((1ULL << n) - 1) & (~((1ULL << m) - 1)) )
#define PFN_MASK BITS_MASK(52, 12)
#define IS_HUGE(pte) (pte & (1ULL << 7))

hpa_t gadget_base(void);
