#include <stdint.h>
#include <stdio.h>
#include <sys/platform/x86.h>

#define KVM_CPUID_SIGNATURE (0x40000000)
#define KVM_CPUID_FEATURES (0x40000001)

struct cpuid_t {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
};

void print_cpuid(struct cpuid_t *c) {
  printf("eax: %x\nebx: %x\necx: %x\nedx: %x\n", c->eax, c->ebx, c->ecx,
         c->edx);
}

#define KVM_FEATURE_CLOCKSOURCE 0
#define KVM_FEATURE_NOP_IO_DELAY 1
#define KVM_FEATURE_MMU_OP 2
#define KVM_FEATURE_CLOCKSOURCE2 3
#define KVM_FEATURE_ASYNC_PF 4
#define KVM_FEATURE_STEAL_TIME 5
#define KVM_FEATURE_PV_EOI 6
#define KVM_FEATURE_PV_UNHALT 7
#define KVM_FEATURE_PV_TLB_FLUSH 9
#define KVM_FEATURE_ASYNC_PF_VMEXIT 10
#define KVM_FEATURE_PV_SEND_IPI 11
#define KVM_FEATURE_POLL_CONTROL 12
#define KVM_FEATURE_PV_SCHED_YIELD 13
#define KVM_FEATURE_ASYNC_PF_INT 14
#define KVM_FEATURE_MSI_EXT_DEST_ID 15
#define KVM_FEATURE_HC_MAP_GPA_RANGE 16
#define KVM_FEATURE_MIGRATION_CONTROL 17
#define KVM_FEATURE_CLOCKSOURCE_STABLE_BIT 24
#define CHECK_AND_PRINT_KVM_FEATURE(feature)                                   \
  if (c->eax & (1 << feature)) {                                               \
    printf(#feature "\n");                                                     \
  }

void print_kvm_features(struct cpuid_t *c) {
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_CLOCKSOURCE);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_NOP_IO_DELAY);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_MMU_OP);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_CLOCKSOURCE2);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_ASYNC_PF);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_STEAL_TIME);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_PV_EOI);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_PV_UNHALT);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_PV_TLB_FLUSH);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_ASYNC_PF_VMEXIT);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_PV_SEND_IPI);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_POLL_CONTROL);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_PV_SCHED_YIELD);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_ASYNC_PF_INT);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_MSI_EXT_DEST_ID);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_HC_MAP_GPA_RANGE);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_MIGRATION_CONTROL);
  CHECK_AND_PRINT_KVM_FEATURE(KVM_FEATURE_CLOCKSOURCE_STABLE_BIT);
}

struct cpuid_t cpuid(uint32_t function) {
  struct cpuid_t c = {0};

  __asm__("cpuid"
          : "=a"(c.eax), "=b"(c.ebx), "=c"(c.ecx), "=d"(c.edx)
          : "a"(function));

  return c;
}

int main() {
  struct cpuid_t kvm = cpuid(KVM_CPUID_SIGNATURE);
  print_cpuid(&kvm);

  struct cpuid_t kvm_features = cpuid(KVM_CPUID_FEATURES);
  print_cpuid(&kvm_features);
  print_kvm_features(&kvm_features);
}
