#include <linux/init.h>   /* Needed for the macros */
#include <linux/module.h> /* Needed by all modules */
#include <linux/printk.h> /* Needed for pr_info() */

static int __init kernel_l1tf_init(void) {
  pr_info("Hello, world 2\n");
  return 0;
}
static void __exit kernel_l1tf_exit(void) { pr_info("Goodbye, world 2\n"); }

module_init(kernel_l1tf_init);
module_exit(kernel_l1tf_exit);
MODULE_LICENSE("GPL");
