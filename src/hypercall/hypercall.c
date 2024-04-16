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
static struct proc_dir_entry *proc_sched_yield;

// Up to four arguments may be passed in rbx, rcx, rdx, and rsi respectively.
// The hypercall number should be placed in rax and the return value will be
// placed in rax. No other registers will be clobbered unless explicitly
// stated by the particular hypercall.
struct hypercall_args {
  uint64_t a0;
  uint64_t a1;
  uint64_t a2;
  uint64_t a3;
};

void inline hypercall(int type, struct hypercall_args real, struct hypercall_args mispredicted) {
  // Confuse the branch predictor
  asm volatile("movq $0, %%rcx\n"
               "cmpq $0, %%rcx\n"
               ".rept 300\n" // TODO: optimize this, maybe 300 is too much/too little?
               "je 1f\n"
               "1:\n"
               ".endr\n" ::
                   : "rcx");

  asm volatile("vmcall" : "+a"(type), "+b"(real.a0), "+c"(real.a1), "+d"(real.a2), "+S"(real.a3));
  asm volatile("vmcall"
               : "+a"(type), "+b"(mispredicted.a0), "+c"(mispredicted.a1), "+d"(mispredicted.a2),
                 "+S"(mispredicted.a3));
}

static ssize_t send_ipi_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {
  struct send_ipi_hypercall_opts opts[2] = {0};

  // Make sure that only the size of the struct is written
  if (len != sizeof(opts)) {
    return -EINVAL;
  }

  // Copy the buffer from the user
  if (copy_from_user(&opts, buff, sizeof(opts))) {
    return -EFAULT;
  }

  struct hypercall_args real = {
      .a0 = opts[0].mask_low, .a1 = opts[0].mask_high, .a2 = opts[0].min, .a3 = opts[0].icr.raw_icr};

  struct hypercall_args mispredicted = {
      .a0 = opts[1].mask_low, .a1 = opts[1].mask_high, .a2 = opts[1].min, .a3 = opts[1].icr.raw_icr};

  hypercall(KVM_HC_SEND_IPI, real, mispredicted);
  return 0;
}

static const struct proc_ops send_ipi_fops = {
    .proc_write = send_ipi_write,
};

static ssize_t sched_yield_write(struct file *file, const char __user *buff, size_t len, loff_t *off) {
  struct sched_yield_opts opts[2] = {0};

  struct hypercall_args real = {0};
  struct hypercall_args fake = {0};
  // Make sure that only the size of the struct is written
  if (len != sizeof(opts)) {
    return -EINVAL;
  }

  // Copy the buffer from the user
  if (copy_from_user(&opts, buff, sizeof(opts))) {
    return -EFAULT;
  }

  real.a0 = opts[0].dest_id;
  fake.a0 = opts[1].dest_id;
  hypercall(KVM_HC_SCHED_YIELD, real, fake);

  return 0;
}
static const struct proc_ops sched_yield_fops = {
    .proc_write = sched_yield_write,
};

static int __init hypercall_main(void) {
  const char *procfs_root_name = "hypercall";
  const char *procfs_ipi_name = "send_ipi";
  const char *procfs_yield_name = "sched_yield";

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

  // Initialize the sched_yield entry
  proc_sched_yield = proc_create(procfs_yield_name, 0666, proc_root, &sched_yield_fops);
  if (NULL == proc_sched_yield) {
    proc_remove(proc_sched_yield);
    proc_remove(proc_send_ipi);
    proc_remove(proc_root);
    pr_alert("Error:Could not initialize /proc/%s/%s\n", procfs_root_name, procfs_yield_name);
    return -ENOMEM;
  }
  pr_info("/proc/%s/%s created\n", procfs_root_name, procfs_yield_name);
  return 0;
}

static void __exit hypercall_exit(void) {
  proc_remove(proc_send_ipi);
  proc_remove(proc_root);
}

module_init(hypercall_main);
module_exit(hypercall_exit);
MODULE_LICENSE("GPL");
