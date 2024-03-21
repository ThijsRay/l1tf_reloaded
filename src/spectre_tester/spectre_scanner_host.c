// You can only do hypercalls from ring 0, so this has to be a kernel module

#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

static int __init main_fn(void) { return 0; }

static void __exit exit_fn(void) { return; }

module_init(main_fn);
module_exit(exit_fn);
MODULE_LICENSE("GPL");
