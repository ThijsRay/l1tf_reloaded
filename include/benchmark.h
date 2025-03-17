#pragma once
#include "config.h"

void display(void *data, int len);
void display_data(char *data);
void benchmark_leakage_primitive(uintptr_t base);
