#pragma once

#define FATHER 0
#define GCE 1
#define AWS 2
#if !defined(MACHINE)
#define MACHINE FATHER
#endif
#if MACHINE == FATHER
#define MACHINE_STR "FATHER"
#elif MACHINE == GCE
#define MACHINE_STR "GCE"
#elif MACHINE == AWS
#define MACHINE_STR "AWS"
#endif

#if !defined(HELPERS)
#define HELPERS 1
#endif

#define L1TF 0
#define SKIP 1
#define CHEAT 2
#define CHEAT_NOISY 3
#if !defined(LEAK)
#define LEAK CHEAT_NOISY
#endif
#if LEAK == L1TF
#define LEAK_STR "L1TF"
#elif LEAK == SKIP
#define LEAK_STR "SKIP"
#elif LEAK == CHEAT
#define LEAK_STR "CHEAT"
#elif LEAK == CHEAT_NOISY
#define LEAK_STR "CHEAT_NOISY"
#endif

#if !HELPERS
static_assert(LEAK == L1TF || LEAK == SKIP);
#endif
