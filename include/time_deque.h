#pragma once
#include <time.h>

#define TIME_DEQUE_NSEC_DIV 1000000000
#define TIME_DEQUE_SIZE 100

struct time_deque {
  struct timespec times[TIME_DEQUE_SIZE];
  struct timespec *head;
  struct timespec *tail;
  size_t count;
};

void time_deque_init(struct time_deque *d);
struct timespec time_deque_pop(struct time_deque *d);
void time_deque_push(struct time_deque *d, struct timespec t);

struct timespec timespec_subtract(struct timespec *x, struct timespec *y);
struct timespec timespec_add(struct timespec *x, struct timespec *y);
double time_deque_average(struct time_deque *d);
