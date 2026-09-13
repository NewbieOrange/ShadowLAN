/* hk_util.c - clock, ms time, log stamp + dlog, sleep, pid, rng.
 * Independent TU; interface in hk_api.h. */
#include "hk_plat.h"
#include "hk_api.h"

long long dt_now_ms(void) {
#ifdef LINUX_BUILD
    struct timeval tv; gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
#else
    return (long long)GetTickCount();
#endif
}

int g_debug = 0;
static unsigned dt_rand_state = 0;
void dt_rand_seed(void) {
    /* NEVER leave the state 0: the default fallback would give every
     * process the SAME random stream, and stream ids (the relay keys
     * streams room-wide by sid) would collide between the viewer tool
     * and the game - and between any two nodes whose processes seed in
     * the same clock tick. Mix pid, ms clock, stack and heap addresses:
     * uniqueness matters more than entropy. */
    unsigned long long x = (unsigned long long)dt_rand_state;
#ifdef LINUX_BUILD
    x ^= (unsigned long long)(unsigned)getpid() * 0x9e3779b97f4a7c15ull;
    x ^= (unsigned long long)(unsigned long)time(NULL) << 17;
    x ^= (unsigned long long)(size_t)(void *)&x >> 4;      /* stack ASLR */
    x ^= (unsigned long long)(size_t)(void *)malloc(1);    /* heap ASLR */
#else
    /* long is 32-bit on EVERY Windows ABI - accumulate in 64 bits so
     * the high-fold below actually folds something */
    x ^= (unsigned long long)GetCurrentProcessId() * 0x9e3779b97f4a7c15ull;
    x ^= GetTickCount64() << 17;
    x ^= (unsigned long long)(size_t)(void *)&x >> 4;
    x ^= (unsigned long long)(size_t)(void *)HeapCreate(0, 0, 0);
#endif
    if (!x) x = 0x9e3779b97f4a7c15ull;
    dt_rand_state = (unsigned)(x ^ (x >> 32));
    if (!dt_rand_state) dt_rand_state = 0x9e3779b9u;
}
unsigned dt_rand(void) {
    unsigned x = dt_rand_state;
    if (!x) { dt_rand_seed(); x = dt_rand_state; }
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    dt_rand_state = x;
    return x ? x : 1;
}
void dt_msleep(int ms) {
#ifdef LINUX_BUILD
    usleep((useconds_t)ms * 1000);
#else
    Sleep(ms);
#endif
}
unsigned current_pid(void) {
#ifdef LINUX_BUILD
    return (unsigned)getpid();
#else
    return GetCurrentProcessId();
#endif
}
void dt_stamp(char *out, size_t n) {
#ifdef LINUX_BUILD
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    snprintf(out, n, "%02d-%02d %02d:%02d:%02d.%03d",
             tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
             (int)(tv.tv_usec / 1000));
#else
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(out, n, "%02d-%02d %02d:%02d:%02d.%03d",
             (int)st.wMonth, (int)st.wDay, (int)st.wHour,
             (int)st.wMinute, (int)st.wSecond, (int)st.wMilliseconds);
#endif
    out[n - 1] = 0;
}
void dlog(const char *m) {
    if (!g_debug) return;
#ifdef LINUX_BUILD
    { char ts[32]; dt_stamp(ts, sizeof(ts)); fprintf(stderr, "[%s lan_hook] %s\n", ts, m); }
#else
    OutputDebugStringA("lan_hook: ");
    OutputDebugStringA(m);
    OutputDebugStringA("\n");
    {
        static FILE *lf = NULL;
        static int tried = 0;
        if (!tried) {
            tried = 1;
            const char *p = getenv("LAN_HOOK_LOGFILE");
            if (p && p[0]) lf = fopen(p, "a");
        }
        if (lf) {
            char ts[32];
            dt_stamp(ts, sizeof(ts));
            fputs(ts, lf); fputs(" lan_hook: ", lf);
            fputs(m, lf); fputc('\n', lf); fflush(lf);
        }
    }
#endif
}

/* fold extra entropy into the stream (node-id minting); seed-safe */
void dt_rand_mix(unsigned v) { dt_rand_state ^= v; }
