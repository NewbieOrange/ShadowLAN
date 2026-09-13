#include "hk_mod.h"

/* hk_winnic.c - adapter identity shim */
/* ---- interface-identity shim --------------------------------------
 * A virtual-NIC product would expose the tunnel address as a real local
 * interface; without a driver we fake that view per-process: the vnode
 * appears as a STANDALONE pseudo-adapter ("ShadowLAN Virtual Interface",
 * up, /24) appended to the adapter lists returned by the IP Helper
 * APIs. Consumers that enumerate "my IPs", compute per-interface
 * broadcast ranges, or sanity-check peers against local subnets (via
 * FirstUnicastAddress or the adapter walk) then see 10.200.0.x exactly
 * like a real LAN interface; binds to it are rewritten to INADDR_ANY.
 * Pure data surgery on caller-owned buffers; failures degrade to the
 * unshimmed answer. ---- */
#define DT_SL_IFINDEX 0x7F000001u /* pseudo-adapter if-index (high, stable) */
PFN_GetAdaptersAddresses p_GetAdaptersAddresses = 0;
PFN_GetAdaptersInfo p_GetAdaptersInfo = 0;
static int g_gaa_logged = 0;

static int dt_vnode_str(char *out, int n) {
    return dt_src_ip(out, (size_t)n);
}

/* Build one pseudo-adapter node at base+off (caller buffer). Strings live
 * in the DLL's .rdata (loaded for the whole process lifetime), so only the
 * adapter struct + its unicast node/sockaddr occupy the buffer. */
#define DT_SL_NAME_A "ShadowLAN Virtual Interface"
#define DT_SL_NAME_W L"ShadowLAN Virtual Interface"
static size_t dt_gaa_sizes(size_t *anode, size_t *unode) {
    *anode = (sizeof(IP_ADAPTER_ADDRESSES) + 15u) & ~(size_t)15;
    *unode = (sizeof(IP_ADAPTER_UNICAST_ADDRESS) + sizeof(SOCKADDR_IN) + 15u) & ~(size_t)15;
    return *anode + *unode;
}
static void dt_gaa_fill(BYTE *base, size_t off, size_t anode, size_t unode, const char *ip) {
    IP_ADAPTER_ADDRESSES *na = (IP_ADAPTER_ADDRESSES *)(base + off);
    memset(na, 0, anode);
    na->Length = sizeof(IP_ADAPTER_ADDRESSES);
    na->IfIndex = DT_SL_IFINDEX;
    na->IfType = IF_TYPE_ETHERNET_CSMACD;
    na->OperStatus = IfOperStatusUp;
    na->Mtu = 1500;
    na->TransmitLinkSpeed = 1000000000ull;
    na->ReceiveLinkSpeed = 1000000000ull;
    /* locally-administered MAC, ASCII "SH" (ShadowLAN) in bytes 2-3 */
    na->PhysicalAddress[0] = 0x02;
    na->PhysicalAddress[1] = 0x00;
    na->PhysicalAddress[2] = 0x53;
    na->PhysicalAddress[3] = 0x48;
    na->PhysicalAddress[4] = 0x00;
    na->PhysicalAddress[5] = 0x01;
    na->PhysicalAddressLength = 6;
    na->AdapterName = (PCHAR)DT_SL_NAME_A;
    na->Description = (PWCHAR)DT_SL_NAME_W;
    na->FriendlyName = (PWCHAR)DT_SL_NAME_W;
    {
        static const wchar_t empty[] = L"";
        na->DnsSuffix = (PWCHAR)empty;
    }
    IP_ADAPTER_UNICAST_ADDRESS *nu = (IP_ADAPTER_UNICAST_ADDRESS *)(base + off + anode);
    memset(nu, 0, unode);
    nu->Length = sizeof(IP_ADAPTER_UNICAST_ADDRESS);
    nu->Next = NULL;
    nu->Address.lpSockaddr = (PSOCKADDR)(base + off + anode + sizeof(IP_ADAPTER_UNICAST_ADDRESS));
    nu->Address.iSockaddrLength = sizeof(SOCKADDR_IN);
    nu->PrefixOrigin = IpPrefixOriginManual;
    nu->SuffixOrigin = IpSuffixOriginManual;
    nu->DadState = IpDadStatePreferred;
    nu->ValidLifetime = 0xFFFFFFFFu;
    nu->PreferredLifetime = 0xFFFFFFFFu;
    nu->LeaseLifetime = 0xFFFFFFFFu;
    nu->OnLinkPrefixLength = 24;
    SOCKADDR_IN *sa = (SOCKADDR_IN *)nu->Address.lpSockaddr;
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_addr.s_addr = inet_addr(ip);
    na->FirstUnicastAddress = nu;
}

ULONG WINAPI hk_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
                                     PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer) {
    ULONG r, used, room, at;
    size_t anode, unode;
    char ip[48];
    if (!p_GetAdaptersAddresses) return ERROR_FUNCTION_FAILED;
    if (g_debug && !g_gaa_logged) {
        g_gaa_logged = 1;
        dlog("GAA shim active");
    }
    if (!g_direct || !dt_vnode_str(ip, sizeof(ip)))
        return p_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
    if (Family != AF_INET && Family != AF_UNSPEC)
        return p_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
    room = SizePointer ? *SizePointer : 0;
    dt_gaa_sizes(&anode, &unode);
    if (g_lan_only) {
        /* Isolated: the pseudo-interface is the ONLY interface this process
         * has. Synthesize a complete one-adapter answer; never touch the
         * real adapter list (that would leak the physical LAN's IPs). */
        ULONG need = (ULONG)(anode + unode);
        if (Family == AF_INET6) {
            if (SizePointer) *SizePointer = 0;
            return ERROR_NO_DATA;
        }
        if (!AdapterAddresses || !SizePointer || room < need) {
            if (SizePointer) *SizePointer = need;
            return ERROR_BUFFER_OVERFLOW;
        }
        dt_gaa_fill((BYTE *)AdapterAddresses, 0, anode, unode, ip);
        AdapterAddresses->Next = NULL;
        *SizePointer = need;
        return NO_ERROR;
    }
    r = p_GetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);
    if (r == ERROR_BUFFER_OVERFLOW) {
        ULONG need = SizePointer ? *SizePointer : 0;
        if (need < 0xFFFFFFFFu - 2560 && SizePointer) *SizePointer = need + 2560;
        return r;
    }
    if (r != NO_ERROR || !AdapterAddresses || !SizePointer) return r;
    used = *SizePointer;
    { /* some implementations report the whole buffer as "used"; trust a
         * fresh size probe (NULL buffer) when it says BUFFER_OVERFLOW */
        ULONG probe = 0;
        if (p_GetAdaptersAddresses(Family, Flags, Reserved, NULL, &probe) ==
                ERROR_BUFFER_OVERFLOW &&
            probe && probe < used)
            used = probe;
    }
    at = (used + 15u) & ~15u;
    if (at + anode + unode <= room) {
        dt_gaa_fill((BYTE *)AdapterAddresses, at, anode, unode, ip);
        ((IP_ADAPTER_ADDRESSES *)((BYTE *)AdapterAddresses + at))->Next = NULL;
        { /* append after the real adapters */
            IP_ADAPTER_ADDRESSES *a = AdapterAddresses;
            while (a && a->Next) a = a->Next;
            if (a) a->Next = (IP_ADAPTER_ADDRESSES *)((BYTE *)AdapterAddresses + at);
        }
        *SizePointer = (ULONG)(at + anode + unode);
    }
    return r;
}

/* Windows-SDK layout of the legacy IP_ADAPTER_INFO (iprtrmib.h). Some
 * compiler SDKs ship a different or truncated definition (older mingw has
 * no DnsServerList), so the surgery below walks its own byte-exact layout
 * and treats the caller buffer opaquely. Lease times are time_t: 8 bytes
 * on x64; on x86 we slightly over-reserve, which is harmless. */
typedef struct dt_ms_ipa_str {
    struct dt_ms_ipa_str *Next;
    char IpAddress[16];
    char IpMask[16];
    DWORD Context;
} dt_ms_ipa_str;
typedef struct dt_ms_ip_adapter_info {
    struct dt_ms_ip_adapter_info *Next;
    DWORD ComboIndex;
    char AdapterName[256 + 4];
    char Description[128 + 4];
    UINT AddressLength;
    unsigned char Address[8];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    dt_ms_ipa_str *CurrentIpAddress;
    dt_ms_ipa_str IpAddressList;
    dt_ms_ipa_str GatewayList;
    dt_ms_ipa_str DnsServerList;
    dt_ms_ipa_str DhcpServer;
    UINT HaveWins;
    dt_ms_ipa_str PrimaryWinsServer;
    dt_ms_ipa_str SecondaryWinsServer;
    long long LeaseObtained;
    long long LeaseExpires;
} dt_ms_ip_adapter_info;

static size_t dt_gai_node(void) {
    return (sizeof(dt_ms_ip_adapter_info) + 15u) & ~(size_t)15;
}
static void dt_gai_fill(BYTE *base, size_t off, const char *ip) {
    dt_ms_ip_adapter_info *na = (dt_ms_ip_adapter_info *)(base + off);
    memset(na, 0, sizeof(*na));
    strncpy(na->AdapterName, DT_SL_NAME_A, sizeof(na->AdapterName) - 1);
    strncpy(na->Description, DT_SL_NAME_A, sizeof(na->Description) - 1);
    na->AddressLength = 6;
    na->Address[0] = 0x02;
    na->Address[1] = 0x00;
    na->Address[2] = 0x53;
    na->Address[3] = 0x48;
    na->Address[4] = 0x00;
    na->Address[5] = 0x01;
    na->Index = DT_SL_IFINDEX;
    na->Type = 6; /* MIB_IF_TYPE_ETHERNET */
    na->DhcpEnabled = 0;
    na->CurrentIpAddress = &na->IpAddressList;
    strncpy(na->IpAddressList.IpAddress, ip, sizeof(na->IpAddressList.IpAddress) - 1);
    strncpy(na->IpAddressList.IpMask, "255.255.255.0", sizeof(na->IpAddressList.IpMask) - 1);
    na->IpAddressList.Next = NULL;
    na->Next = NULL;
}

ULONG WINAPI hk_GetAdaptersInfo(PIP_ADAPTER_INFO InfoBuffer, PULONG SizePointer) {
    ULONG r, used, at, room;
    char ip[48];
    size_t ino;
    if (!p_GetAdaptersInfo) return ERROR_FUNCTION_FAILED;
    if (!g_direct || !dt_vnode_str(ip, sizeof(ip)))
        return p_GetAdaptersInfo(InfoBuffer, SizePointer);
    room = SizePointer ? *SizePointer : 0;
    ino = dt_gai_node();
    if (g_lan_only) { /* isolated: one-adapter answer, real list hidden */
        if (!InfoBuffer || !SizePointer || room < (ULONG)ino) {
            if (SizePointer) *SizePointer = (ULONG)ino;
            return ERROR_BUFFER_OVERFLOW;
        }
        dt_gai_fill((BYTE *)InfoBuffer, 0, ip);
        *SizePointer = (ULONG)ino;
        return NO_ERROR;
    }
    r = p_GetAdaptersInfo(InfoBuffer, SizePointer);
    if (r == ERROR_BUFFER_OVERFLOW) {
        ULONG need = SizePointer ? *SizePointer : 0;
        if (need < 0xFFFFFFFFu - 2048 && SizePointer) *SizePointer = need + 2048;
        return r;
    }
    if (r != NO_ERROR || !InfoBuffer || !SizePointer) return r;
    used = *SizePointer;
    { /* same whole-buffer-as-used quirk as GetAdaptersAddresses: clamp
         * to a fresh size probe when it reports the true packed size */
        ULONG probe = 0;
        if (p_GetAdaptersInfo(NULL, &probe) == ERROR_BUFFER_OVERFLOW && probe && probe < used)
            used = probe;
    }
    at = (used + 15u) & ~15u;
    if (at + ino <= room) {
        dt_gai_fill((BYTE *)InfoBuffer, at, ip);
        { /* append after the real adapters (Next is offset 0 in both
             * SDK spellings, so the walk is safe) */
            dt_ms_ip_adapter_info *a = (dt_ms_ip_adapter_info *)InfoBuffer;
            while (a && a->Next) a = a->Next;
            if (a) a->Next = (dt_ms_ip_adapter_info *)((BYTE *)InfoBuffer + at);
        }
        *SizePointer = (ULONG)(at + ino);
    }
    return r;
}

/* Optional module allowlist (LAN_HOOK_MODULES=a.dll,b.dll): only patch
 * modules whose file name contains one of these (case-insensitive).
 * Escape hatch when a specific DLL (overlay, anti-tamper, ...) misbehaves.
 * Empty = patch everything. */
int module_allowed(const char *path) {
    const char *list = getenv("LAN_HOOK_MODULES");
    if (!list || !list[0]) return 1;
    const char *base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    const char *slash = strrchr(base, '/');
    base = slash ? slash + 1 : base;
    char tmp[1024];
    strncpy(tmp, list, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = 0;
    for (char *t = strtok(tmp, ",;"); t; t = strtok(NULL, ",;")) {
        while (*t == ' ') t++;
        if (!*t) continue;
        const char *a = base, *b = t;
        /* case-insensitive substring */
        for (; *a; a++) {
            const char *x = a;
            const char *y = b;
            while (*y && tolower((unsigned char)*x) == tolower((unsigned char)*y)) {
                x++;
                y++;
            }
            if (!*y) return 1;
        }
    }
    return 0;
}

void patch_iat_inner(HMODULE mod) {
    if (!mod) return;
    int patched = 0;
    char modname[MAX_PATH] = {0};
    if (g_debug) {
        GetModuleFileNameA(mod, modname, sizeof(modname) - 1);
        char *bs = strrchr(modname, '\\');
        memmove(modname, bs ? bs + 1 : modname, strlen(bs ? bs + 1 : modname) + 1);
    }
    {
        BYTE *base = (BYTE *)mod;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        if (dos->e_lfanew <= 0 || dos->e_lfanew > 1024 * 1024) return;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        IMAGE_DATA_DIRECTORY *impdir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!impdir->VirtualAddress) return;
        IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(base + impdir->VirtualAddress);
        for (; desc->Name; desc++) {
            char *dll = (char *)(base + desc->Name);
            int isws2 = (_stricmp(dll, "ws2_32.dll") == 0);
            int isk32 = (_stricmp(dll, "kernel32.dll") == 0);
            int isiph = (_stricmp(dll, "iphlpapi.dll") == 0);
            if (!isws2 && !isk32 && !isiph) continue;
            IMAGE_THUNK_DATA *orig = desc->OriginalFirstThunk
                                         ? (IMAGE_THUNK_DATA *)(base + desc->OriginalFirstThunk)
                                         : 0;
            IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA *)(base + desc->FirstThunk);
            HMODULE hExp = GetModuleHandleA(dll);
            for (; iat->u1.Function; iat++, orig ? orig++ : 0) {
                char *fn = 0;
                char ordname[40];
                /* Ordinal-ness must come from the import lookup table:
                 * the loader overwrites the IAT with resolved addresses,
                 * so testing the IAT slot itself misses every ordinal
                 * import (this hid MinGW-linked socket I/O entirely). */
                IMAGE_THUNK_DATA *lu = orig ? orig : iat;
                if (IMAGE_SNAP_BY_ORDINAL(lu->u1.Ordinal)) {
                    const char *rn = export_name_for_ordinal(hExp, IMAGE_ORDINAL(lu->u1.Ordinal));
                    if (!rn) continue;
                    strncpy(ordname, rn, sizeof(ordname) - 1);
                    ordname[sizeof(ordname) - 1] = 0;
                    fn = ordname;
                } else {
                    IMAGE_IMPORT_BY_NAME *nm =
                        (IMAGE_IMPORT_BY_NAME *)(base + lu->u1.AddressOfData);
                    if (!nm) continue;
                    fn = (char *)nm->Name;
                }
                FARPROC rep = 0;
                if (isws2) {
                    if (!strcmp(fn, "sendto")) rep = (FARPROC)hk_sendto;
                    else if (!strcmp(fn, "recvfrom")) rep = (FARPROC)hk_recvfrom;
                    else if (!strcmp(fn, "accept")) rep = (FARPROC)hk_accept;
                    else if (!strcmp(fn, "WSASendTo")) rep = (FARPROC)hk_WSASendTo;
                    else if (!strcmp(fn, "WSARecvFrom")) rep = (FARPROC)hk_WSARecvFrom;
                    else if (!strcmp(fn, "connect")) rep = (FARPROC)hk_connect;
                    else if (!strcmp(fn, "bind")) rep = (FARPROC)hk_bind;
                    else if (!strcmp(fn, "WSAConnect")) rep = (FARPROC)hk_WSAConnect;
                    else if (!strcmp(fn, "getpeername")) rep = (FARPROC)hk_getpeername;
                    else if (!strcmp(fn, "shutdown")) rep = (FARPROC)hk_shutdown;
                    else if (!strcmp(fn, "getsockopt")) rep = (FARPROC)hk_getsockopt;
                    else if (!strcmp(fn, "getsockname")) rep = (FARPROC)hk_getsockname;
                    else if (!strcmp(fn, "closesocket")) rep = (FARPROC)hk_closesocket;
                    else if (!strcmp(fn, "listen")) rep = (FARPROC)hk_listen;
                    else if (!strcmp(fn, "send")) rep = (FARPROC)hk_send;
                    else if (!strcmp(fn, "recv")) rep = (FARPROC)hk_recv;
                    else if (!strcmp(fn, "WSASend")) rep = (FARPROC)hk_WSASend;
                    else if (!strcmp(fn, "WSARecv")) rep = (FARPROC)hk_WSARecv;
                    else if (!strcmp(fn, "ioctlsocket")) rep = (FARPROC)hk_ioctlsocket;
                    else if (!strcmp(fn, "select")) rep = (FARPROC)hk_select;
                    else if (!strcmp(fn, "WSAPoll")) rep = (FARPROC)hk_WSAPoll;
                    else if (!strcmp(fn, "WSAEventSelect")) rep = (FARPROC)hk_WSAEventSelect;
                    else if (!strcmp(fn, "WSAEnumNetworkEvents"))
                        rep = (FARPROC)hk_WSAEnumNetworkEvents;
                    else if (!strcmp(fn, "WSAWaitForMultipleEvents"))
                        rep = (FARPROC)hk_WSAWaitForMultipleEvents;
                    else if (!strcmp(fn, "WSACreateEvent")) rep = (FARPROC)hk_WSACreateEvent;
                    else if (!strcmp(fn, "WSACloseEvent")) rep = (FARPROC)hk_WSACloseEvent;
                } else if (isiph && !strcmp(fn, "GetAdaptersAddresses")) {
                    rep = (FARPROC)hk_GetAdaptersAddresses;
                } else if (isiph && !strcmp(fn, "IcmpSendEcho")) {
                    rep = (FARPROC)hk_IcmpSendEcho;
                } else if (isiph && !strcmp(fn, "IcmpSendEcho2")) {
                    rep = (FARPROC)hk_IcmpSendEcho2;
                } else if (isiph && !strcmp(fn, "GetAdaptersInfo")) {
                    rep = (FARPROC)hk_GetAdaptersInfo;
                } else if (isk32 && !strcmp(fn, "GetProcAddress")) {
                    rep = (FARPROC)hk_GetProcAddress;
                } else if (isk32 && !strcmp(fn, "LoadLibraryA")) {
                    rep = (FARPROC)hk_LoadLibraryA;
                } else if (isk32 && !strcmp(fn, "LoadLibraryW")) {
                    rep = (FARPROC)hk_LoadLibraryW;
                } else if (isk32 && !strcmp(fn, "LoadLibraryExA")) {
                    rep = (FARPROC)hk_LoadLibraryExA;
                } else if (isk32 && !strcmp(fn, "LoadLibraryExW")) {
                    rep = (FARPROC)hk_LoadLibraryExW;
                } else if (isk32 && !strcmp(fn, "ExitProcess")) {
                    rep = (FARPROC)hk_ExitProcess;
                } else if (isk32 && !strcmp(fn, "TerminateProcess")) {
                    rep = (FARPROC)hk_TerminateProcess;
                } else if (isk32 && !strcmp(fn, "CreateProcessA")) {
                    rep = (FARPROC)hk_CreateProcessA;
                } else if (isk32 && !strcmp(fn, "CreateProcessW")) {
                    rep = (FARPROC)hk_CreateProcessW;
                }
                if (rep) {
                    DWORD old = 0;
                    if (VirtualProtect(&iat->u1.Function, sizeof(void *), PAGE_READWRITE, &old)) {
                        iat->u1.Function = (ULONG_PTR)rep;
                        VirtualProtect(&iat->u1.Function, sizeof(void *), old, &old);
                        if (g_debug && patched < 256) {
                            char lb[160];
                            snprintf(lb, sizeof(lb), "patch iat %s!%s", modname, fn);
                            dlog(lb);
                            patched++;
                        }
                    }
                }
            }
        }
    }
}
