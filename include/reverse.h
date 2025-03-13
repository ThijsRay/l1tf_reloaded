#pragma once

typedef uint64_t u64; // virtual address
typedef unsigned long va_t; // virtual address
typedef unsigned long pa_t; // physical address
typedef unsigned long gva_t; // guest virtual address
typedef unsigned long gpa_t; // guest physical address
typedef unsigned long hva_t; // host virtual address
typedef unsigned long hpa_t; // host physical address
typedef unsigned long pte_t; // page table entry - pfn is host physical

void get_feeling_for_kernel_kvm_data_structures(void);
void reverse_host_kernel_data_structures(void);
