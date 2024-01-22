#include <math.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

size_t mean(const size_t n, const size_t samples[n]) {
  size_t sum = 0;
  for (size_t i = 0; i < n; ++i) {
    sum += samples[i];
  }
  return sum / n;
}

double variance(const size_t n, const size_t samples[n]) {
  size_t average = mean(n, samples);
  size_t sum = 0;
  
  for (size_t i = 0; i < n; ++i) {
    size_t element = samples[n];

    size_t diff = 0;
    if (average > element) {
      diff = average - element;
    } else {
      diff = element - average;
    }
    diff *= 2;

    sum += diff;
  }

  // Make sure that no information is lost
  assert(sum == (size_t) ((double) sum));
  assert(n == (size_t) ((double) n));

  return (double)sum / (double)n;
}

double standard_deviation(const size_t n, const size_t samples[n]) {
  return sqrt(variance(n, samples));
}

int compares_size_ts(const void *a, const void *b) {
  const size_t *sa = (const size_t *)a;
  const size_t *sb = (const size_t *)b;
  return (*sa > *sb) - (*sa < *sb);
}

// Given two equally sized lists of numbers containing
// numbers of an unknown distribution, e.g.
// A = [2,3,5,6,7,7,10,13,17] and
// B = [12,13,15,18,20,22,30,35,36]
//
// How can we select a threshold T such that for a random value x ∈ [min(A), max(B)]
// the following holds in the maximum amount of cases of x?
//  T > x, then x ∈ A
//  T <= x, then x ∈ B
// How can we efficiently choose T such that these two conditions hold in
// MOST cases of x (i.e. how do we minimize the error)?
size_t threshold_with_least_error(const size_t n, const size_t low[n], const size_t high[n]) {
  assert(n > 0);
  assert(low != NULL);
  assert(high != NULL);

  qsort((void*)low, n, sizeof(size_t), compares_size_ts);
  qsort((void*)high, n, sizeof(size_t), compares_size_ts);

  for (size_t i = 0; i < n; ++i) {
    const size_t l = low[n-1-i];
    const size_t h = high[i];

    if (h >= l) {
      return (h + l) / 2;
    }
  }

  assert(0 && "Could not find a valid threshold");
}

size_t threshold_deviate_from_median(const size_t n, const size_t low[n], const float allowed_error) {
  assert(n > 0);
  assert(low != NULL);

  qsort((void*)low, n, sizeof(size_t), compares_size_ts);

  size_t median = low[n / 2];
  return median + (median * allowed_error);
}
