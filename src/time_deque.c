#include <assert.h>
#include <string.h>

#include "time_deque.h"

void time_deque_init(struct time_deque *d) {
  memset(d, 0, sizeof(struct time_deque));
  d->head = &d->times[0];
  d->tail = &d->times[0];
}

struct timespec time_deque_pop(struct time_deque *d) {
  assert(d->count);
  assert(d->count <= TIME_DEQUE_SIZE);

  struct timespec t = *(d->tail);
  d->tail++;
  d->count--;
  if (d->tail == &d->times[TIME_DEQUE_SIZE]) {
    d->tail = &d->times[0];
  }

  assert(d->count < TIME_DEQUE_SIZE);
  return t;
}

void time_deque_push(struct time_deque *d, struct timespec t) {
  if (d->count == TIME_DEQUE_SIZE) {
    time_deque_pop(d);
  }

  assert(d->count < TIME_DEQUE_SIZE);
  *(d->head) = t;
  d->head++;
  d->count++;
  if (d->head == &d->times[TIME_DEQUE_SIZE]) {
    d->head = &d->times[0];
  }

  assert(d->count <= TIME_DEQUE_SIZE);
}

struct timespec timespec_subtract(struct timespec *x, struct timespec *y) {
  /* Perform the carry for the later subtraction by updating y. */
  if (x->tv_nsec < y->tv_nsec) {
    int sec = (y->tv_nsec - x->tv_nsec) / TIME_DEQUE_NSEC_DIV + 1;
    y->tv_nsec -= TIME_DEQUE_NSEC_DIV * sec;
    y->tv_sec += sec;
  }
  if (x->tv_nsec - y->tv_nsec > TIME_DEQUE_NSEC_DIV) {
    int sec = (x->tv_nsec - y->tv_nsec) / TIME_DEQUE_NSEC_DIV;
    y->tv_nsec += TIME_DEQUE_NSEC_DIV * sec;
    y->tv_sec -= sec;
  }

  /* Compute the time remaining to wait
     tv_usec is certainly positive. */
  struct timespec result;
  result.tv_sec = x->tv_sec - y->tv_sec;
  result.tv_nsec = x->tv_nsec - y->tv_nsec;
  return result;
}

struct timespec timespec_add(struct timespec *x, struct timespec *y) {
  struct timespec result = {0};
  result.tv_nsec = x->tv_nsec + y->tv_nsec;
  int sec = result.tv_nsec / TIME_DEQUE_NSEC_DIV + 1;
  result.tv_nsec -= TIME_DEQUE_NSEC_DIV * sec;
  result.tv_sec = x->tv_sec + y->tv_sec + sec;
  return result;
}

double time_deque_average(struct time_deque *d) {
  double r = 0;

  if (!d->count) {
    return r;
  }

  struct timespec sum = {0};
  struct timespec *cursor = d->tail;
  do {
    sum = timespec_add(&sum, cursor);
    cursor++;
    if (cursor == &d->times[TIME_DEQUE_SIZE]) {
      cursor = &d->times[0];
    }
  } while (cursor != d->head);

  r = sum.tv_sec + ((double)sum.tv_nsec / TIME_DEQUE_NSEC_DIV);
  return r / d->count;
}
