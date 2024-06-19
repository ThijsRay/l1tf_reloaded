#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "hypercall.h"

#define MAX_PHYS_MEMORY (34359738368)

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_search_for_page;

static char symbol[] = "kvm_emulate_hypercall";
static struct kprobe kp = {
    .symbol_name = symbol,
};

static uintptr_t PAGE_ADDR = 0;
static uintptr_t MAP_ADDR = 0;

static size_t calculate_min(const uintptr_t phys_page_addr, const uintptr_t phys_map_addr) {
  // It is below the phys_map, and thus unreachable
  if (phys_page_addr < phys_map_addr) {
    return 0;
  }

  return (phys_page_addr - phys_map_addr) / 8;
}

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

  MAP_ADDR = (uintptr_t)&map->phys_map[0];
  pr_info("map->phys_map[0] is at %px (phys addr: %px)\n", (void *)MAP_ADDR,
          (void *)virt_to_phys((void *)MAP_ADDR));

  if (MAP_ADDR && PAGE_ADDR) {
    pr_info("index into map->phys_map is 0x%lx (phys addr: %px)\n", calculate_min(PAGE_ADDR, MAP_ADDR),
            (void *)virt_to_phys((void *)PAGE_ADDR));
  }
  return 0;
}

static ssize_t search_for_page(struct file *file, const char __user *buff, size_t len, loff_t *off) {
  uint64_t page_value;

  if (len != sizeof(page_value)) {
    return -EINVAL;
  }

  if (copy_from_user(&page_value, buff, sizeof(page_value))) {
    return -EFAULT;
  }

  // Search for the page!
  for (long unsigned int page = page_offset_base; page < page_offset_base + MAX_PHYS_MEMORY;
       page += PAGE_SIZE) {

    uint64_t value;
    if (get_kernel_nofault(value, (uint64_t *)page)) {
      continue;
    }

    if (value == page_value) {
      PAGE_ADDR = page;
      pr_info("kvm_assist: leak page is at %px\n", (void *)PAGE_ADDR);
      return 0;
    }
  }
  pr_info("kvm_assist: leak page not found\n");
  return 0;
}

static const struct proc_ops search_for_page_fops = {
    .proc_write = search_for_page,
};

static int __init kvm_assist_main(void) {
  int ret;
  kp.pre_handler = handler_pre;

  ret = register_kprobe(&kp);
  if (ret < 0) {
    pr_err("register_kprobe failed, returned %d\n", ret);
    return ret;
  }

  pr_info("Planted kprobe at %p\n", kp.addr);

  // Initialize the root procfs entry
  const char *procfs_root_name = "kvm_assist";
  proc_root = proc_mkdir(procfs_root_name, NULL);
  if (!proc_root) {
    proc_remove(proc_root);
    pr_alert("hypercall: Error: Could not initialize /proc/%s\n", procfs_root_name);
    return -ENOMEM;
  }

  // Initialize the search_for_page entry
  const char *procfs_search_for_page = "search_for_page";
  proc_search_for_page = proc_create(procfs_search_for_page, 0666, proc_root, &search_for_page_fops);
  if (!proc_search_for_page) {
    proc_remove(proc_search_for_page);
    proc_remove(proc_root);
    pr_alert("hypercall: Error:Could not initialize /proc/%s/%s\n", procfs_root_name, procfs_search_for_page);
    return -ENOMEM;
  }

  return 0;
}

static void __exit kvm_assist_exit(void) {
  proc_remove(proc_search_for_page);
  proc_remove(proc_root);
  unregister_kprobe(&kp);
  return;
}

module_init(kvm_assist_main);
module_exit(kvm_assist_exit);
MODULE_LICENSE("GPL");
