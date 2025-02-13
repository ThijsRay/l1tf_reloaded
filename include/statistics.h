#pragma once
#include <stddef.h>

size_t maximum(const size_t n, const size_t x[n]);

size_t mean(const size_t n, const size_t samples[n]);

double variance(const size_t n, const size_t samples[n]);

double standard_deviation(const size_t n, const size_t samples[n]);

int compares_size_ts(const void *a, const void *b);

size_t median(const size_t n, size_t samples[n]);

void sort(const size_t n, size_t samples[n]);
size_t threshold_with_least_error(const size_t n, const size_t low[n],
                                  const size_t high[n]);

size_t threshold_deviate_from_median(const size_t n, const size_t low[n],
                                     const float allowed_error);

long rand64(void);
