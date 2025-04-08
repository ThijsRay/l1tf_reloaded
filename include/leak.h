#pragma once
#include "config.h"
#include "reverse.h"
#include "util.h"
#include "helpers.h"

#define BITS_MASK(n, m) ( ((1ULL << n) - 1) & (~((1ULL << m) - 1)) )
#define PFN_MASK BITS_MASK(52, 12)
#define IS_HUGE(pte) (pte & (1ULL << 7))

extern u64 leak_attempts;
hpa_t gadget_base(void);
void leak(void *data, hpa_t base, hpa_t pa, int len);
u64 leak64(hpa_t base, hpa_t pa);
int is_kernel_ptr(va_t va, va_t dm);
int in_direct_map(va_t va, va_t dm);
int in_vmalloc(va_t va, va_t dm);
hva_t leak_ptr(hpa_t base, va_t dm, hpa_t pa, int (*check)(va_t, va_t));
pte_t leak_pte(hpa_t base, hpa_t pa);
hpa_t translate(hpa_t base, hva_t va, hpa_t cr3, hva_t hdm, const char *prefmt, ...);
hpa_t translate_tdp(hpa_t base, gva_t va, gva_t gdm, hpa_t gcr3, hpa_t eptp);
hpa_t translate2gpa(hpa_t base, gva_t va, gva_t gdm, hpa_t gcr3, hpa_t eptp);
