/* Launcher with env-from-args.
 *
 *   injector.exe [--server HOST] [--port PORT] [--token SECRET]
 *                [--ports LIST] [--udp-over-tcp] [-e KEY=VAL]... [--debug] [--]
 *                <hook.dll> <game.exe> [game args...]
 *
 * Each option maps to the hook's env (child inherits it):
 *   --server -> LAN_HOOK_SERVER   (relay address; required)
 *   --port   -> LAN_HOOK_PORT     (default 47777)
 *   --token  -> LAN_HOOK_TOKEN    (room key, must match relay --token)
 *   --ports  -> LAN_HOOK_PORTS    (e.g. 4444,27015,7777; empty = all LAN)
 *   --udp-over-tcp -> LAN_HOOK_UDP_OVER_TCP=1 (game UDP over the TCP link; for
 *                peers behind NATs/firewalls that filter inbound UDP.
 *                Game args after the exe pass through untouched.)
 *   -e K=V   -> generic extra env
 *   --debug  -> LAN_HOOK_DEBUG=1
 *
 * Back-compat: injector.exe hook.dll game.exe [game args...] still works.
 * Use "--" when game args start with "-": injector.exe --server X -- hook.dll game.exe -windowed
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Remote module base WITHOUT truncation: thread exit codes are DWORD,
 * so a 64-bit HMODULE never survives GetExitCodeThread. Enumerate the
 * target's modules instead (same handle we already own). */
static HMODULE find_remote(HANDLE hProcess, const char *dllfull) {
    static HMODULE mods[2048];
    DWORD need = 0;
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &need)) return NULL;
    DWORD n = need / sizeof(HMODULE);
    if (n > 2048) n = 2048;
    for (DWORD i = 0; i < n; i++) {
        char path[MAX_PATH] = {0};
        if (GetModuleFileNameExA(hProcess, mods[i], path, sizeof(path)) &&
            _stricmp(path, dllfull) == 0)
            return mods[i];
    }
    return NULL;
}

static void usage(void) {
    fprintf(stderr,
        "usage: injector.exe [--server HOST] [--port PORT] [--token SECRET]\n"
        "                    [--ports LIST] [--udp-over-tcp] [-e KEY=VAL]... [--debug] [--]\n"
        "                    <hook.dll> <game.exe> [game args...]\n"
        "example: injector.exe --server 203.0.113.10 --port 47777 --token SECRET -- lan_hook64.dll game.exe -windowed\n");
}

static int starts_with(const char *s, const char *pre) {
    return strncmp(s, pre, strlen(pre)) == 0;
}

int main(int argc, char **argv) {
    const char *server = NULL, *port = NULL, *token = NULL, *ports = NULL;
    int debug = 0, udptcp = 0;
    int i = 1;
    /* collect leading options; stop at "--" or first non-option */
    int opts_done = 0;
    for (; i < argc && !opts_done; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { i++; break; }
        if (!strcmp(a, "--server") && i + 1 < argc) server = argv[++i];
        else if (starts_with(a, "--server=")) server = a + 9;
        else if (!strcmp(a, "--port") && i + 1 < argc) port = argv[++i];
        else if (starts_with(a, "--port=")) port = a + 7;
        else if (!strcmp(a, "--token") && i + 1 < argc) token = argv[++i];
        else if (starts_with(a, "--token=")) token = a + 8;
        else if (!strcmp(a, "--ports") && i + 1 < argc) ports = argv[++i];
        else if (starts_with(a, "--ports=")) ports = a + 8;
        else if (!strcmp(a, "--udp-over-tcp")) udptcp = 1;
        else if (!strcmp(a, "--debug")) debug = 1;
        else if (!strcmp(a, "-e") && i + 1 < argc) {
            char *kv = argv[++i], *eq = strchr(kv, '=');
            if (!eq) { fprintf(stderr, "-e needs KEY=VAL\n"); return 2; }
            *eq = 0;
            SetEnvironmentVariableA(kv, eq + 1);
        } else if (starts_with(a, "-e") && strlen(a) > 2) {
            char *kv = _strdup(a + 2), *eq = strchr(kv, '=');
            if (!eq) { fprintf(stderr, "-e needs KEY=VAL\n"); return 2; }
            *eq = 0;
            SetEnvironmentVariableA(kv, eq + 1);
            free(kv);
        } else if (a[0] == '-' && a[1] != 0) {
            fprintf(stderr, "unknown option %s\n", a);
            usage();
            return 2;
        } else {
            break; /* dll */
        }
    }
    if (server) SetEnvironmentVariableA("LAN_HOOK_SERVER", server);
    if (port) SetEnvironmentVariableA("LAN_HOOK_PORT", port);
    if (token) SetEnvironmentVariableA("LAN_HOOK_TOKEN", token);
    if (ports) SetEnvironmentVariableA("LAN_HOOK_PORTS", ports);
    if (udptcp) SetEnvironmentVariableA("LAN_HOOK_UDP_OVER_TCP", "1");
    if (debug) SetEnvironmentVariableA("LAN_HOOK_DEBUG", "1");

    if (argc - i < 2) { usage(); return 2; }
    const char *dll = argv[i++];
    /* remaining argv[i..] is game + game args (may start with '-') */
    char cmd[8192] = {0};
    for (int j = i; j < argc; j++) {
        if (j > i) strcat(cmd, " ");
        if (strchr(argv[j], ' ')) { strcat(cmd, "\""); strcat(cmd, argv[j]); strcat(cmd, "\""); }
        else strcat(cmd, argv[j]);
    }
    char dllfull[MAX_PATH];
    GetFullPathNameA(dll, sizeof(dllfull), dllfull, NULL);

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed %lu\n", GetLastError());
        return 1;
    }
    size_t n = strlen(dllfull) + 1;
    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) { fprintf(stderr, "VirtualAllocEx %lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 1; }
    if (!WriteProcessMemory(pi.hProcess, mem, dllfull, n, NULL)) {
        fprintf(stderr, "WriteProcessMemory %lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 1;
    }
    HMODULE k = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE fn = (LPTHREAD_START_ROUTINE)GetProcAddress(k, "LoadLibraryA");
    HANDLE th = CreateRemoteThread(pi.hProcess, NULL, 0, fn, mem, 0, NULL);
    if (!th) { fprintf(stderr, "CreateRemoteThread %lu\n", GetLastError()); TerminateProcess(pi.hProcess, 1); return 1; }
    WaitForSingleObject(th, INFINITE);
    DWORD code = 0; GetExitCodeThread(th, &code);
    CloseHandle(th); VirtualFreeEx(pi.hProcess, mem, 0, MEM_RELEASE);
    if (!code) { fprintf(stderr, "remote LoadLibrary failed\n"); TerminateProcess(pi.hProcess, 1); return 1; }
    /* Stage 2: run LanHookInit on a normal remote thread (outside the
     * loader lock). The remote base comes from module enumeration:
     * thread exit codes are DWORD and would truncate a 64-bit HMODULE.
     * The RVA is file-layout derived, so ASLR-independent. */
    {
        HMODULE local = LoadLibraryA(dllfull);
        if (local) {
            FARPROC localInit = GetProcAddress(local, "LanHookInit");
            HMODULE remote = find_remote(pi.hProcess, dllfull);
            if (localInit && remote) {
                uintptr_t rva = (uintptr_t)localInit - (uintptr_t)local;
                LPTHREAD_START_ROUTINE rInit =
                    (LPTHREAD_START_ROUTINE)((uintptr_t)remote + rva);
                HANDLE th2 = CreateRemoteThread(pi.hProcess, NULL, 0, rInit,
                                                NULL, 0, NULL);
                if (!th2) {
                    fprintf(stderr, "warning: LanHookInit remote thread failed %lu (hook loaded but idle)\n",
                            GetLastError());
                } else {
                    WaitForSingleObject(th2, INFINITE);
                    DWORD st = 1;
                    GetExitCodeThread(th2, &st);
                    CloseHandle(th2);
                    if (st == 200 || st == 201) {
                        /* hook already showed the fatal messagebox and is
                         * terminating the game; make sure it never resumes */
                        fprintf(stderr, "ShadowLAN fatal (%lu): %s\n", st,
                                st == 200 ? "cannot reach relay"
                                          : "no virtual-IP lease from relay");
                        TerminateProcess(pi.hProcess, st);
                        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                        return (int)st;
                    } else if (st == 2)
                        fprintf(stderr, "warning: LanHookInit hit a guarded fault; "
                                "see lan_hook_<pid>.dmp next to the game and the hook log\n");
                    else if (st != 0)
                        fprintf(stderr, "warning: LanHookInit returned %lu\n", st);
                    else
                        printf("hook initialized\n");
                }
            } else {
                fprintf(stderr, "warning: old DLL without LanHookInit (hook loaded but idle)\n");
            }
            FreeLibrary(local);
        }
    }
    ResumeThread(pi.hThread);
    {
        /* NOTE: getenv() is stale under mingw/msvcrt (startup snapshot),
         * so read the live OS environment for display. The child always
         * inherits the values set above regardless. */
        char srv[256] = "(unset)", prt[32] = "47777", tok[16] = "(unset)";
        if (GetEnvironmentVariableA("LAN_HOOK_SERVER", srv, sizeof(srv)) == 0) strcpy(srv, "(unset)");
        if (GetEnvironmentVariableA("LAN_HOOK_PORT", prt, sizeof(prt)) == 0) strcpy(prt, "47777");
        if (GetEnvironmentVariableA("LAN_HOOK_TOKEN", tok, sizeof(tok)) != 0) strcpy(tok, "set");
        printf("injected %s -> pid %lu server=%s port=%s token=%s\n",
               dllfull, (unsigned long)pi.dwProcessId, srv, prt, tok);
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}
