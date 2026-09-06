/* Launcher with env-from-args.
 *
 *   injector.exe [--server HOST] [--port PORT] [--token SECRET]
 *                [--ports LIST] [-e KEY=VAL]... [--debug] [--]
 *                <hook.dll> <game.exe> [game args...]
 *
 * Each option maps to the hook's env (child inherits it):
 *   --server -> LAN_HOOK_SERVER   (relay address; required)
 *   --port   -> LAN_HOOK_PORT     (default 47777)
 *   --token  -> LAN_HOOK_TOKEN    (room key, must match relay --token)
 *   --ports  -> LAN_HOOK_PORTS    (e.g. 4444,27015,7777; empty = all LAN)
 *   -e K=V   -> generic extra env
 *   --debug  -> LAN_HOOK_DEBUG=1
 *
 * Back-compat: injector.exe hook.dll game.exe [game args...] still works.
 * Use "--" when game args start with "-": injector.exe --server X -- hook.dll game.exe -windowed
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void usage(void) {
    fprintf(stderr,
        "usage: injector.exe [--server HOST] [--port PORT] [--token SECRET]\n"
        "                    [--ports LIST] [-e KEY=VAL]... [--debug] [--]\n"
        "                    <hook.dll> <game.exe> [game args...]\n"
        "example: injector.exe --server 203.0.113.10 --port 47777 --token SECRET -- lan_hook64.dll game.exe -windowed\n");
}

static int starts_with(const char *s, const char *pre) {
    return strncmp(s, pre, strlen(pre)) == 0;
}

int main(int argc, char **argv) {
    const char *server = NULL, *port = NULL, *token = NULL, *ports = NULL;
    int debug = 0;
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
    ResumeThread(pi.hThread);
    printf("injected %s -> pid %lu server=%s port=%s token=%s\n", dllfull, (unsigned long)pi.dwProcessId,
           getenv("LAN_HOOK_SERVER") ? getenv("LAN_HOOK_SERVER") : "(unset)",
           getenv("LAN_HOOK_PORT") ? getenv("LAN_HOOK_PORT") : "47777",
           getenv("LAN_HOOK_TOKEN") ? "set" : "(unset)");
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}
