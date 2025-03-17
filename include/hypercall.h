#pragma once
#include "config.h"

#if __has_include(<stdint.h>)
#include <stdbool.h>
#include <stdint.h>
#else
#include <linux/types.h>
#endif

enum icr_delivery_mode {
  ICR_DELIVERY_MODE_FIXED = 0,
  ICR_DELIVERY_MODE_LOWEST_PRIO = 1,
  ICR_DELIVERY_MODE_SMI = 2,
  ICR_DELIVERY_MODE_RESERVED1 = 3,
  ICR_DELIVERY_MODE_NMI = 4,
  ICR_DELIVERY_MODE_INIT = 5,
  ICR_DELIVERY_MODE_STARTUP = 6,
  ICR_DELIVERY_MODE_RESERVED2 = 7,
};

enum icr_destination_mode {
  ICR_DESTINATION_MODE_PHYSICAL = 0,
  ICR_DESTINATION_MODE_LOGICAL = 1,
};

enum icr_delivery_status {
  ICR_DELIVERY_STATUS_IDLE = 0,
  ICR_DELIVERY_STATUS_SEND_PENDING = 1,
};

enum icr_level {
  ICR_LEVEL_DEASSERT = 0,
  ICR_LEVEL_ASSERT = 1,
};

enum icr_trigger_mode {
  ICR_TRIGGER_MODE_EDGE = 0,
  ICR_TRIGGER_MODE_LEVEL = 1,
};

enum icr_destination_shorthand {
  ICR_DESTINATION_SHORTHAND_NONE = 0,
  ICR_DESTINATION_SHORTHAND_SELF = 1,
  ICR_DESTINATION_SHORTHAND_ALL_INCL_SELF = 2,
  ICR_DESTINATION_SHORTHAND_ALL_EXCL_SELF = 3,
};

struct __attribute__((packed)) icr {
  uint8_t vector : 8;
  enum icr_delivery_mode delivery_mode : 3;
  enum icr_destination_mode : 1;
  enum icr_delivery_status : 1;
  bool __reserved1 : 1;
  enum icr_level : 1;
  enum icr_trigger_mode : 1;
  int __reserved2 : 2;
  enum icr_destination_shorthand : 2;
  uint64_t __reserved36 : 36;
  uint8_t destination : 8;
};

_Static_assert(sizeof(struct icr) == sizeof(unsigned long), "struct icr should be 8 bytes");

struct send_ipi_hypercall_opts {
  unsigned long mask_low;
  unsigned long mask_high;
  union {
    struct icr icr;
    unsigned long raw_icr;
  } icr;
  uint32_t min;
};

struct self_send_ipi_hypercall {
  uint32_t min;
  int repeat;
};

struct send_ipi_hypercall {
  struct send_ipi_hypercall_opts real;
  struct send_ipi_hypercall_opts mispredicted;
  void *ptr;
};

struct sched_yield_hypercall {
  unsigned long current_cpu_id;
  unsigned long speculated_cpu_id;
  void *ptr;
};
