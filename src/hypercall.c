#include <linux/kvm_para.h>
#include <stdint.h>
#include <stdio.h>

// Up to four arguments may be passed in rbx, rcx, rdx, and rsi respectively.
// The hypercall number should be placed in rax and the return value will be
// placed in rax. No other registers will be clobbered unless explicitly
// stated by the particular hypercall.
uint64_t hypercall(int type, uint64_t a0, uint64_t a1, uint64_t a2,
                   uint64_t a3) {
  uint64_t rax = type;
  asm volatile inline("vmcall"
                      : "+a"(rax), "=b"(a0), "=c"(a1), "=d"(a2), "=S"(a3));
  return rax;
}

// a0: lower part of the bitmap of destination APIC IDs
// a1: higher part of the bitmap of destination APIC IDs
// a2: the lowest APIC ID in bitmap
// a3: APIC ICR
int send_ipi(unsigned long ipi_bitmap_low, unsigned long ipi_bitmap_high,
             uint32_t min, unsigned long icr) {
  return hypercall(KVM_HC_SEND_IPI, ipi_bitmap_low, ipi_bitmap_high, min, icr);
}

int main() {
  unsigned long mask_low = 0xdeadbeef;
  unsigned long mask_high = 0xcafebabe;
  uint32_t min = 100;
  unsigned long icr = 0;

  int count = send_ipi(mask_low, mask_high, min, icr);
  printf("Send to %d CPUs\n", count);
  return 0;
}
