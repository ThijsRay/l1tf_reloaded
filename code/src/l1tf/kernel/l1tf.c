#include "linux/proc_fs.h"
#include <linux/init.h>   /* Needed for the macros */
#include <linux/module.h> /* Needed by all modules */
#include <linux/printk.h> /* Needed for pr_info() */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thijs Raymakers");
MODULE_DESCRIPTION("Run L1tf in kernel space");

static struct proc_dir_entry *l1tf_proc_dir;
static struct proc_dir_entry *scan_phys_mem;

static const struct proc_ops scan_phys_mem_fops = {

};

static int setup_proc_fs(void) {
  // Initialize the base directory
  l1tf_proc_dir = proc_mkdir("l1tf", NULL);
  if (!l1tf_proc_dir) {
    pr_alert("l1tf: Error - Could not initialize /proc/l1tf\n");
    return -ENOMEM;
  }

  scan_phys_mem =
      proc_create("scan_phys_mem", 0600, l1tf_proc_dir, &scan_phys_mem_fops);
  if (!scan_phys_mem) {
    pr_alert("l1tf: Error - Could not initialize /proc/l1tf/scan_phys_mem\n");
    return -ENOMEM;
  }

  return 0;
}

static void teardown_proc_fs(void) {
  proc_remove(scan_phys_mem);
  proc_remove(l1tf_proc_dir);
}

static int __init l1tf_init(void) {
  int error = 0;
  pr_info("l1tf: Initializing module\n");

  error = setup_proc_fs();
  if (error)
    return error;

  if (!error) {
    pr_info("l1tf: Initialized module!\n");
  }
  return error;
}
static void __exit l1tf_exit(void) {
  teardown_proc_fs();
  pr_info("l1tf: Removed module\n");
}

module_init(l1tf_init);
module_exit(l1tf_exit);
