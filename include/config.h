#pragma once

#define FATHER 0
#define GCE 1
#define AWS 2
#if !defined(MACHINE)
        // Pick the physical machine you are attacking.
        #define MACHINE GCE
#endif
#if MACHINE == FATHER
        #define MACHINE_STR "FATHER"
#elif MACHINE == GCE
        #define MACHINE_STR "GCE"
#elif MACHINE == AWS
        #define MACHINE_STR "AWS"
#endif

#if !defined(HELPERS)
        // Are there helper-hypercalls installed on the host?
        #define HELPERS 0
#endif

#define L1TF 0
#define SKIP 1
#define CHEAT 2
#define CHEAT_NOISY 3
#if !defined(LEAK)
        // Pick your data leaking method.
        #define LEAK L1TF
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

#define NOISINESS 100 // Out of 1024