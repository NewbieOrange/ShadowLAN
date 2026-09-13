/* hk_wininst.inc - IAT patching, env publish, LanHookInit, DllMain (Windows only)
 * Part of lan_hook.c; see the note there before editing. */
#ifndef LINUX_BUILD

/* Guarded entry points: a bad module is skipped, never fatal. */
/* Patching is re-entrant across threads (init, LoadLibrary hooks on app
 * threads, the late-module sweep): serialize it. The shared SEH jump
 * buffer is only sound under this lock. */
static CRITICAL_SECTION g_pcs;
static int g_pcs_init = 0;
#define DT_MAXSEEN 1024
static HMODULE g_seen[DT_MAXSEEN];
static int g_nseen = 0;

static void patch_iat(HMODULE mod) {
    if (!mod) return;
    if (!g_pcs_init) return;
    EnterCriticalSection(&g_pcs);
    if (mod != g_hself) {
        char path[MAX_PATH] = {0};
        if (GetModuleFileNameA(mod, path, sizeof(path) - 1) &&
            !module_allowed(path)) {
            dbg("lan_hook: module not in allowlist, skipped\n");
            LeaveCriticalSection(&g_pcs);
            return;
        }
    }
    if (setjmp(g_seh_jb) != 0) {
        dbg("lan_hook: skipped unreadable module\n");
        LeaveCriticalSection(&g_pcs);
        return;
    }
    g_seh_armed = 1;
    patch_iat_inner(mod);
    g_seh_armed = 0;
    {   /* remember: the sweep only revisits modules it has never seen */
        int i, have = 0;
        for (i = 0; i < g_nseen; i++) if (g_seen[i] == mod) { have = 1; break; }
        if (!have && g_nseen < DT_MAXSEEN) g_seen[g_nseen++] = mod;
    }
    LeaveCriticalSection(&g_pcs);
}

static void patch_all(int force) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) { patch_iat(GetModuleHandleA(NULL)); return; }
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    int n = 0;
    /* skip our own module: tunnel threads must call the real Winsock */
    if (Module32First(snap, &me)) do {
        if (me.hModule == g_hself || me.hModule == NULL) continue;
        if (!force) {
            int i, have = 0;
            EnterCriticalSection(&g_pcs);
            for (i = 0; i < g_nseen; i++) if (g_seen[i] == me.hModule) { have = 1; break; }
            LeaveCriticalSection(&g_pcs);
            if (have) continue;
        }
        patch_iat(me.hModule);
        n++;
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    if (force || n > 0) {
        char lb[96];
        snprintf(lb, sizeof(lb), force ? "lan_hook: patched %d modules\n"
                                       : "lan_hook: late-patched %d new modules\n", n);
        dbg(lb);
    }
}

/* Game engines routinely grab networking plugin DLLs long after our
 * install pass. LoadLibrary hooks catch the common case, but a direct
 * ntdll loader call bypasses every user-mode import hook, so keep a
 * slow differential sweep as a safety net: cheap module-list diff,
 * patch anything new once. */
static DWORD WINAPI dt_sweep_thread(LPVOID u) {
    (void)u;
    for (;;) {
        Sleep(2000);
        patch_all(0);
    }
    return 0;
}

/* LoadLibrary hooks: patch newcomers too. */
static PFN_LoadLibraryA p_LoadLibraryA = 0; static PFN_LoadLibraryW p_LoadLibraryW = 0;
static PFN_LoadLibraryExA p_LoadLibraryExA = 0; static PFN_LoadLibraryExW p_LoadLibraryExW = 0;
HMODULE WINAPI hk_LoadLibraryA(LPCSTR n) { HMODULE h = p_LoadLibraryA(n); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryW(LPCWSTR n) { HMODULE h = p_LoadLibraryW(n); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl) { HMODULE h = p_LoadLibraryExA(n,f,fl); if (h && h != g_hself) patch_iat(h); return h; }
HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl) { HMODULE h = p_LoadLibraryExW(n,f,fl); if (h && h != g_hself) patch_iat(h); return h; }

/* Sub-process hooking: a launcher tool that
 * spawns the real game gets the hook carried into each child automatically.
 * Same bitness only (Windows cannot cross-inject); failures fall back to
 * launching unhooked rather than breaking the game. Filter with
 * LAN_HOOK_CHILDREN=a.exe,b.exe (substring list, empty = all children);
 * LAN_HOOK_NOCHILD=1 disables child injection entirely. */
typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);
static PFN_CreateProcessA p_CreateProcessA = 0;
static PFN_CreateProcessW p_CreateProcessW = 0;

static int child_wanted(const char *image) {
    const char *e = getenv("LAN_HOOK_NOCHILD");
    if (e && e[0] == '1') return 0;
    e = getenv("LAN_HOOK_CHILDREN");
    if (!e || !e[0]) return 1;
    if (!image || !image[0]) return 1;
    {
        char tmp[1024];
        strncpy(tmp, e, sizeof(tmp) - 1);
        tmp[sizeof(tmp) - 1] = 0;
        for (char *t = strtok(tmp, ",;"); t; t = strtok(NULL, ",;")) {
            while (*t == ' ') t++;
            if (!*t) continue;
            const char *a = image;
            for (; *a; a++) {
                const char *x = a; const char *y = t;
                while (*y && tolower((unsigned char)*x) == tolower((unsigned char)*y)) { x++; y++; }
                if (!*y) return 1;
            }
        }
    }
    return 0;
}

/* image path of the child for the name filter (app name, else argv[0]). */
static void child_image(const char *app, const char *cmd, char *out, size_t n) {
    const char *src;
    int quoted = 0;
    if (!n) return;
    if (app && app[0]) {
        strncpy(out, app, n - 1);
        out[n - 1] = 0;
        return;
    }
    if (!cmd) { out[0] = 0; return; }
    src = cmd;
    while (*src == ' ') src++;
    if (*src == '"') { quoted = 1; src++; }
    {
        size_t i = 0;
        for (; *src && i + 1 < n; src++) {
            if (quoted ? (*src == '"') : (*src == ' ')) break;
            out[i++] = *src;
        }
        out[i] = 0;
    }
}

static void inject_child(PROCESS_INFORMATION *pi) {
    char dllpath[MAX_PATH] = {0};
    LPVOID mem;
    size_t n;
    HMODULE k;
    LPTHREAD_START_ROUTINE fn;
    HANDLE th;
    DWORD code = 0;
    if (!GetModuleFileNameA(g_hself, dllpath, sizeof(dllpath) - 1)) return;
    n = strlen(dllpath) + 1;
    mem = VirtualAllocEx(pi->hProcess, NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;
    if (!WriteProcessMemory(pi->hProcess, mem, dllpath, n, NULL)) {
        VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE);
        return;
    }
    k = GetModuleHandleA("kernel32.dll");
    fn = (LPTHREAD_START_ROUTINE)GetProcAddress(k, "LoadLibraryA");
    th = CreateRemoteThread(pi->hProcess, NULL, 0, fn, mem, 0, NULL);
    if (!th) { VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE); return; }
    if (WaitForSingleObject(th, 30000) != WAIT_OBJECT_0) {
        dbg("lan_hook: child LoadLibrary timed out, continuing unhooked\n");
        CloseHandle(th);
        VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE);
        return;
    }
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    VirtualFreeEx(pi->hProcess, mem, 0, MEM_RELEASE);
    if (!code) {
        dbg("lan_hook: child LoadLibrary failed (bitness?), continuing unhooked\n");
        return;
    }
    {
        /* remote base via enumeration (exit codes truncate 64-bit bases) */
        FARPROC localInit = GetProcAddress(g_hself, "LanHookInit");
        if (localInit) {
            HMODULE mods[512];
            DWORD need = 0;
            if (EnumProcessModules(pi->hProcess, mods, sizeof(mods), &need)) {
                DWORD cnt = need / sizeof(HMODULE);
                DWORD i;
                if (cnt > 512) cnt = 512;
                for (i = 0; i < cnt; i++) {
                    char path[MAX_PATH] = {0};
                    if (GetModuleFileNameExA(pi->hProcess, mods[i], path, sizeof(path) - 1) &&
                        _stricmp(path, dllpath) == 0) {
                        uintptr_t rva = (uintptr_t)localInit - (uintptr_t)g_hself;
                        LPTHREAD_START_ROUTINE rInit =
                            (LPTHREAD_START_ROUTINE)((uintptr_t)mods[i] + rva);
                        HANDLE th2 = CreateRemoteThread(pi->hProcess, NULL, 0, rInit, NULL, 0, NULL);
                        if (th2) {
                            DWORD st = 1;
                            if (WaitForSingleObject(th2, 30000) == WAIT_OBJECT_0)
                                GetExitCodeThread(th2, &st);
                            CloseHandle(th2);
                            if (st != 0) dbg("lan_hook: child init non-zero\n");
                        }
                        break;
                    }
                }
            }
        }
    }
    dbg("lan_hook: child injected\n");
}

/* Tree identity, explicit-env case: with lpEnvironment==NULL the child
 * inherits our stamped process env already. When the caller supplies an
 * explicit block (CREATE_NEW_ENVIRONMENT), append LAN_HOOK_NODE to it so
 * the child still joins the parent's node. Returns a malloc'd replacement
 * block (caller frees) or the original when untouched. */
static LPVOID dt_env_with_node(LPVOID env, DWORD flags) {
    char num[24];
    if (!env || !g_node) return env;
    snprintf(num, sizeof num, "%u", g_node);
    if (flags & CREATE_UNICODE_ENVIRONMENT) {
        static const WCHAR nm[] = L"LAN_HOOK_NODE=";
        const WCHAR *p = (const WCHAR *)env;
        size_t n = 0;
        int found = 0;
        while (p[n]) {
            if (!_wcsnicmp(p + n, nm, 14)) found = 1;
            n += wcslen(p + n) + 1;
        }
        if (found) return env;
        {
            WCHAR *blk = (WCHAR *)malloc((n + 48) * sizeof(WCHAR));
            if (!blk) return env;
            memcpy(blk, p, n * sizeof(WCHAR));
            {
                WCHAR *q = blk + n;
                memcpy(q, nm, sizeof(nm) - sizeof(WCHAR));
                q += 14;
                MultiByteToWideChar(CP_UTF8, 0, num, -1, q, 16);
                q += wcslen(q);
                q[0] = 0;   /* string terminator + block terminator */
                q[1] = 0;
            }
            return blk;
        }
    } else {
        const char *p = (const char *)env;
        size_t n = 0;
        int found = 0;
        while (p[n]) {
            if (!_strnicmp(p + n, "LAN_HOOK_NODE=", 14)) found = 1;
            n += strlen(p + n) + 1;
        }
        if (found) return env;
        {
            char *blk = (char *)malloc(n + 48);
            if (!blk) return env;
            memcpy(blk, p, n);
            {
                int w = snprintf(blk + n, 32, "LAN_HOOK_NODE=%s", num);
                blk[n + (size_t)w + 1] = 0;   /* double-null terminate */
            }
            return blk;
        }
    }
}

BOOL WINAPI hk_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
                              LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD flags,
                              LPVOID env, LPCSTR dir, LPSTARTUPINFOA si,
                              LPPROCESS_INFORMATION pi) {
    char image[MAX_PATH] = {0};
    BOOL wantSuspend;
    BOOL ok;
    if (!p_CreateProcessA) return FALSE;
    child_image(app, cmd, image, sizeof(image));
    if (!child_wanted(image)) {
        dbg("lan_hook: child not in filter, launching unhooked\n");
        return p_CreateProcessA(app, cmd, pa, ta, inh, flags, env, dir, si, pi);
    }
    wantSuspend = (flags & CREATE_SUSPENDED) != 0;
    {
        LPVOID cenv = dt_env_with_node(env, flags);
        ok = p_CreateProcessA(app, cmd, pa, ta, inh, flags | CREATE_SUSPENDED,
                              cenv, dir, si, pi);
        if (cenv != env) free(cenv);
    }
    if (!ok) return FALSE;
    inject_child(pi);
    if (!wantSuspend) ResumeThread(pi->hThread);
    return TRUE;
}

BOOL WINAPI hk_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                              LPSECURITY_ATTRIBUTES ta, BOOL inh, DWORD flags,
                              LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                              LPPROCESS_INFORMATION pi) {
    char image[MAX_PATH] = {0};
    char appA[MAX_PATH] = {0}, cmdA[8192] = {0};
    BOOL wantSuspend;
    BOOL ok;
    if (!p_CreateProcessW) return FALSE;
    if (app) WideCharToMultiByte(CP_UTF8, 0, app, -1, appA, sizeof(appA) - 1, NULL, NULL);
    if (cmd) WideCharToMultiByte(CP_UTF8, 0, cmd, -1, cmdA, sizeof(cmdA) - 1, NULL, NULL);
    child_image(app ? appA : NULL, cmd ? cmdA : NULL, image, sizeof(image));
    if (!child_wanted(image)) {
        dbg("lan_hook: child not in filter, launching unhooked\n");
        return p_CreateProcessW(app, cmd, pa, ta, inh, flags, env, dir, si, pi);
    }
    wantSuspend = (flags & CREATE_SUSPENDED) != 0;
    {
        LPVOID cenv = dt_env_with_node(env, flags);
        ok = p_CreateProcessW(app, cmd, pa, ta, inh, flags | CREATE_SUSPENDED,
                              cenv, dir, si, pi);
        if (cenv != env) free(cenv);
    }
    if (!ok) return FALSE;
    inject_child(pi);
    if (!wantSuspend) ResumeThread(pi->hThread);
    return TRUE;
}

static void patch_loader_iat_inner(void) {
    /* patch kernel32 LoadLibrary imports in exe so future DLLs get hooked */
    HMODULE exe = GetModuleHandleA(NULL);
    BYTE *base = (BYTE*)exe;
    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR*)(base +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; desc->Name; desc++) {
            char *dll = (char*)(base + desc->Name);
            if (_stricmp(dll, "kernel32.dll")) continue;
            IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA*)(base + desc->FirstThunk);
            IMAGE_THUNK_DATA *orig = desc->OriginalFirstThunk ? (IMAGE_THUNK_DATA*)(base + desc->OriginalFirstThunk) : 0;
            HMODULE hExp = GetModuleHandleA("kernel32.dll");
            for (; iat->u1.Function; iat++, orig ? orig++ : 0) {
                char *fn = 0;
                char ordname[40];
                IMAGE_THUNK_DATA *lu = orig ? orig : iat;
                if (IMAGE_SNAP_BY_ORDINAL(lu->u1.Ordinal)) {
                    const char *rn = export_name_for_ordinal(
                        hExp, IMAGE_ORDINAL(lu->u1.Ordinal));
                    if (!rn) continue;
                    strncpy(ordname, rn, sizeof(ordname) - 1);
                    ordname[sizeof(ordname) - 1] = 0;
                    fn = ordname;
                } else {
                    IMAGE_IMPORT_BY_NAME *nm = (IMAGE_IMPORT_BY_NAME*)(base + lu->u1.AddressOfData);
                    if (!nm) continue;
                    fn = (char*)nm->Name;
                }
                FARPROC rep = 0;
                if (!strcmp(fn, "LoadLibraryA")) rep = (FARPROC)hk_LoadLibraryA;
                else if (!strcmp(fn, "LoadLibraryW")) rep = (FARPROC)hk_LoadLibraryW;
                else if (!strcmp(fn, "LoadLibraryExA")) rep = (FARPROC)hk_LoadLibraryExA;
                else if (!strcmp(fn, "LoadLibraryExW")) rep = (FARPROC)hk_LoadLibraryExW;
                if (rep) {
                    DWORD old = 0;
                    if (VirtualProtect(&iat->u1.Function, sizeof(void*), PAGE_READWRITE, &old)) {
                        iat->u1.Function = (ULONG_PTR)rep;
                        VirtualProtect(&iat->u1.Function, sizeof(void*), old, &old);
                    }
                }
            }
        }
    }
}

static void patch_loader_iat(void) {
    if (setjmp(g_seh_jb) != 0) {
        dbg("lan_hook: skipped unreadable exe imports\n");
        return;
    }
    g_seh_armed = 1;
    patch_loader_iat_inner();
    g_seh_armed = 0;
}

/* Two-stage init: DllMain does nothing but record our handle (running
 * under the loader lock is no place for threads or patching). The
 * injector calls LanHookInit on a normal remote thread after
 * LoadLibrary succeeds. Returns 0 on success. */
__declspec(dllexport) DWORD WINAPI LanHookInit(LPVOID unused) {
    static volatile LONG done = 0;
    if (InterlockedCompareExchange(&done, 1, 0) != 0)
        return 0; /* already initialized */
    (void)unused;
    flog_open();
    flog("LanHookInit: enter");
    AddVectoredExceptionHandler(1, seh_filter);
    if (setjmp(g_init_jb) != 0) {
        /* guarded fault anywhere below: leave a dump, keep game alive */
        flog("LanHookInit: guarded fault during init");
        write_minidump();
        return 2;
    }
    g_init_armed = 1;
    if (!g_dcs_init) { InitializeCriticalSection(&g_dcs); g_dcs_init = 1; }
    flog("LanHookInit: resolving imports");
    hWS2 = GetModuleHandleA("ws2_32.dll");
    if (!hWS2) hWS2 = LoadLibraryA("ws2_32.dll");
    hKernel = GetModuleHandleA("kernel32.dll");
    dbg("lan_hook: resolving imports\n");
    p_sendto = (PFN_sendto)GetProcAddress(hWS2, "sendto");
    p_recvfrom = (PFN_recvfrom)GetProcAddress(hWS2, "recvfrom");
    p_accept = (PFN_accept)GetProcAddress(hWS2, "accept");
    p_WSASendTo = (PFN_WSASendTo)GetProcAddress(hWS2, "WSASendTo");
    p_WSARecvFrom = (PFN_WSARecvFrom)GetProcAddress(hWS2, "WSARecvFrom");
    p_connect = (PFN_connect)GetProcAddress(hWS2, "connect");
    p_bind = (PFN_bind)GetProcAddress(hWS2, "bind");
    p_WSAConnect = (PFN_WSAConnect)GetProcAddress(hWS2, "WSAConnect");
    p_getpeername = (PFN_getpeername)GetProcAddress(hWS2, "getpeername");
    p_getsockname = (PFN_getsockname)GetProcAddress(hWS2, "getsockname");
    {
        HMODULE hIPH = LoadLibraryA("iphlpapi.dll");
        if (hIPH) {
            p_GetAdaptersAddresses = (PFN_GetAdaptersAddresses)GetProcAddress(hIPH, "GetAdaptersAddresses");
            p_GetAdaptersInfo = (PFN_GetAdaptersInfo)GetProcAddress(hIPH, "GetAdaptersInfo");
            p_IcmpSendEcho = (PFN_IcmpSendEcho)GetProcAddress(hIPH, "IcmpSendEcho");
            p_IcmpSendEcho2 = (PFN_IcmpSendEcho2)GetProcAddress(hIPH, "IcmpSendEcho2");
            dbg("lan_hook: iphlpapi pointers resolved\n");
        }
    }
    p_closesocket = (PFN_closesocket)GetProcAddress(hWS2, "closesocket");
    p_listen = (PFN_listen)GetProcAddress(hWS2, "listen");
    p_send = (PFN_send)GetProcAddress(hWS2, "send");
    p_recv = (PFN_recv)GetProcAddress(hWS2, "recv");
    p_WSASend = (PFN_WSASend)GetProcAddress(hWS2, "WSASend");
    p_WSARecv = (PFN_WSARecv)GetProcAddress(hWS2, "WSARecv");
    p_ioctlsocket = (PFN_ioctlsocket)GetProcAddress(hWS2, "ioctlsocket");
    p_WSAEventSelect = (PFN_WSAEventSelect)GetProcAddress(hWS2, "WSAEventSelect");
    p_WSAEnumNetworkEvents = (PFN_WSAEnumNetworkEvents)GetProcAddress(hWS2, "WSAEnumNetworkEvents");
    p_WSAWaitForMultipleEvents = (PFN_WSAWaitForMultipleEvents)GetProcAddress(hWS2, "WSAWaitForMultipleEvents");
    p_WSACreateEvent = (PFN_WSACreateEvent)GetProcAddress(hWS2, "WSACreateEvent");
    p_WSACloseEvent = (PFN_WSACloseEvent)GetProcAddress(hWS2, "WSACloseEvent");
    p_GetProcAddress = (PFN_GetProcAddress)GetProcAddress(hKernel, "GetProcAddress");
    p_CreateProcessA = (PFN_CreateProcessA)GetProcAddress(hKernel, "CreateProcessA");
    p_CreateProcessW = (PFN_CreateProcessW)GetProcAddress(hKernel, "CreateProcessW");
    p_LoadLibraryA = (PFN_LoadLibraryA)GetProcAddress(hKernel, "LoadLibraryA");
    p_LoadLibraryW = (PFN_LoadLibraryW)GetProcAddress(hKernel, "LoadLibraryW");
    p_LoadLibraryExA = (PFN_LoadLibraryExA)GetProcAddress(hKernel, "LoadLibraryExA");
    p_LoadLibraryExW = (PFN_LoadLibraryExW)GetProcAddress(hKernel, "LoadLibraryExW");
    policy_init();
    dbg("lan_hook: policy ready\n");
    flog("LanHookInit: policy ready");
    dt_log_options();
    {
        WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    }
    if (g_direct) { dbg("lan_hook: starting tunnel\n"); flog("LanHookInit: starting tunnel"); dt_start(); }
    dbg("lan_hook: patching modules\n");
    flog("LanHookInit: patching modules");
    InitializeCriticalSection(&g_pcs);
    g_pcs_init = 1;
    patch_all(1);
    patch_loader_iat();
    /* late GetProcAddress IAT swap for already-loaded modules */
    patch_all(1);
    {
        HANDLE t = CreateThread(NULL, 0, dt_sweep_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    dbg("lan_hook: installed\n");
    flog("LanHookInit: ShadowLAN hook v" SHADOWLAN_VERSION);
    flog("LanHookInit: build " __DATE__ " " __TIME__);
    flog("LanHookInit: installed");
    g_init_armed = 0;
    g_init_done = 1;
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {
    (void)r;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hself = h;
        DisableThreadLibraryCalls(h);
    }
    return TRUE;
}

#endif
