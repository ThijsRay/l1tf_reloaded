#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "hypercall.h"

#define MAX_PHYS_MEMORY (34359738368)

static char symbol[] = "kvm_emulate_hypercall";
static struct kprobe kp = {
    .symbol_name = symbol,
};

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs) {
  struct kvm_vcpu *vcpu;
  struct kvm *kvm;
  struct kvm_apic_map *map;

  vcpu = (struct kvm_vcpu *)regs->di;
  if (!vcpu) {
    return 1;
  }

  kvm = vcpu->kvm;
  if (!kvm) {
    return 1;
  }

  rcu_read_lock();
  map = rcu_dereference(kvm->arch.apic_map);
  rcu_read_unlock();

  if (!map) {
    return 1;
  }

  pr_info("map->phys_map[0] is at %px\n", &map->phys_map[0]);
  return 0;
}

static int __init kvm_assist_main(void) {
  int ret;
  kp.pre_handler = handler_pre;

  ret = register_kprobe(&kp);
  if (ret < 0) {
    pr_err("register_kprobe failed, returned %d\n", ret);
    return ret;
  }

  pr_info("Planted kprobe at %p\n", kp.addr);

  for (long unsigned int page = page_offset_base; page < page_offset_base + MAX_PHYS_MEMORY;
       page += PAGE_SIZE) {

    uint64_t value;
    if (get_kernel_nofault(value, (uint64_t *)page)) {
      continue;
    }

    if (value == page_value) {
      pr_info("kvm_assist: leak page is at %px\n", (char *)page);
      return 0;
    }
  }
  pr_info("kvm_assist: leak page not found\n");
  return 0;
}

static void __exit kvm_assist_exit(void) {
  unregister_kprobe(&kp);
  return;
}

module_init(kvm_assist_main);
module_exit(kvm_assist_exit);
MODULE_LICENSE("GPL");
