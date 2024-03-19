#pragma once
#include <stdint.h>

extern uint64_t ret2spec(void *leak_addr, void *reload_buffer0,
                         void *reload_buffer1);
extern uint64_t ret2spec_end(void);
