#ifndef HK_WIN_H
#define HK_WIN_H
#include "hk_core.h"

#ifndef LINUX_BUILD

typedef int(WSAAPI *PFN_sendto)(SOCKET, const char *, int, int, const struct sockaddr *, int);
typedef int(WSAAPI *PFN_recvfrom)(SOCKET, char *, int, int, struct sockaddr *, int *);
typedef SOCKET(WSAAPI *PFN_accept)(SOCKET, struct sockaddr *, int *);
typedef int(WSAAPI *PFN_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr *,
                                   int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int(WSAAPI *PFN_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr *,
                                     LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int(WSAAPI *PFN_connect)(SOCKET, const struct sockaddr *, int);
typedef int(WSAAPI *PFN_bind)(SOCKET, const struct sockaddr *, int);
typedef int(WSAAPI *PFN_WSAConnect)(SOCKET, const struct sockaddr *, int, LPWSABUF, LPWSABUF, LPQOS,
                                    LPQOS);
typedef int(WSAAPI *PFN_getpeername)(SOCKET, struct sockaddr *, int *);
typedef int(WSAAPI *PFN_getsockname)(SOCKET, struct sockaddr *, int *);
typedef int(WSAAPI *PFN_closesocket)(SOCKET);
typedef int(WSAAPI *PFN_listen)(SOCKET, int);
typedef int(WSAAPI *PFN_send)(SOCKET, const char *, int, int);
typedef int(WSAAPI *PFN_recv)(SOCKET, char *, int, int);
typedef int(WSAAPI *PFN_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int(WSAAPI *PFN_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED,
                                 LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int(WSAAPI *PFN_ioctlsocket)(SOCKET, long, u_long *);
typedef int(WSAAPI *PFN_WSAEventSelect)(SOCKET, WSAEVENT, long);
typedef int(WSAAPI *PFN_WSAEnumNetworkEvents)(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);
typedef DWORD(WSAAPI *PFN_WSAWaitForMultipleEvents)(DWORD, const WSAEVENT *, BOOL, DWORD, BOOL);
typedef WSAEVENT(WSAAPI *PFN_WSACreateEvent)(void);
typedef BOOL(WSAAPI *PFN_WSACloseEvent)(WSAEVENT);
typedef FARPROC(WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef HMODULE(WINAPI *PFN_LoadLibraryW)(LPCWSTR);
typedef HMODULE(WINAPI *PFN_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI *PFN_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
typedef void(WINAPI *PFN_ExitProcess)(UINT);
typedef BOOL(WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                                         LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR,
                                         LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                         LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                         LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef ULONG(WINAPI *PFN_GetAdaptersAddresses)(ULONG, ULONG, PVOID, PIP_ADAPTER_ADDRESSES, PULONG);
typedef ULONG(WINAPI *PFN_GetAdaptersInfo)(PIP_ADAPTER_INFO, PULONG);
typedef DWORD(WINAPI *PFN_IcmpSendEcho)(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION,
                                        LPVOID, DWORD, DWORD);
typedef DWORD(WINAPI *PFN_IcmpSendEcho2)(HANDLE, HANDLE, FARPROC, PVOID, IPAddr, LPVOID, WORD,
                                         PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);

extern PFN_sendto p_sendto;
extern PFN_recvfrom p_recvfrom;
extern PFN_accept p_accept;
extern PFN_WSASendTo p_WSASendTo;
extern PFN_WSARecvFrom p_WSARecvFrom;
extern PFN_connect p_connect;
extern PFN_WSAConnect p_WSAConnect;
extern PFN_bind p_bind;
extern PFN_getpeername p_getpeername;
extern PFN_closesocket p_closesocket;
extern PFN_getsockname p_getsockname;
extern PFN_listen p_listen;
extern PFN_send p_send;
extern PFN_recv p_recv;
extern PFN_WSASend p_WSASend;
extern PFN_WSARecv p_WSARecv;
extern PFN_ioctlsocket p_ioctlsocket;
extern PFN_WSAEventSelect p_WSAEventSelect;
extern PFN_WSAEnumNetworkEvents p_WSAEnumNetworkEvents;
extern PFN_WSAWaitForMultipleEvents p_WSAWaitForMultipleEvents;
extern PFN_WSACreateEvent p_WSACreateEvent;
extern PFN_WSACloseEvent p_WSACloseEvent;
extern PFN_GetProcAddress p_GetProcAddress;
extern PFN_ExitProcess p_ExitProcess;
extern BOOL(WINAPI *p_TerminateProcess)(HANDLE, UINT);
extern PFN_LoadLibraryA p_LoadLibraryA;
extern PFN_LoadLibraryW p_LoadLibraryW;
extern PFN_LoadLibraryExA p_LoadLibraryExA;
extern PFN_LoadLibraryExW p_LoadLibraryExW;
extern PFN_CreateProcessA p_CreateProcessA;
extern PFN_CreateProcessW p_CreateProcessW;
extern PFN_GetAdaptersAddresses p_GetAdaptersAddresses;
extern PFN_GetAdaptersInfo p_GetAdaptersInfo;
extern PFN_IcmpSendEcho p_IcmpSendEcho;
extern PFN_IcmpSendEcho2 p_IcmpSendEcho2;

extern HMODULE g_hself;
extern HMODULE hWS2, hKernel;
extern jmp_buf g_seh_jb;
extern volatile LONG g_seh_armed;
extern jmp_buf g_init_jb;
extern volatile LONG g_init_armed;
extern EXCEPTION_POINTERS *g_init_ep;

HK_INT void flog_open(void);
HK_INT void flog(const char *m);
HK_INT void dbg(const char *m);
HK_INT void write_minidump(void);
HK_INT LONG WINAPI seh_filter(EXCEPTION_POINTERS *ep);
HK_INT const char *export_name_for_ordinal(HMODULE mod, DWORD ord);
HK_INT int module_allowed(const char *path);
HK_INT void patch_iat_inner(HMODULE mod);

void WINAPI hk_ExitProcess(UINT code);
BOOL WINAPI hk_TerminateProcess(HANDLE h, UINT code);
BOOL WINAPI hk_CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
                              DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI hk_CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL,
                              DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
HMODULE WINAPI hk_LoadLibraryA(LPCSTR n);
HMODULE WINAPI hk_LoadLibraryW(LPCWSTR n);
HMODULE WINAPI hk_LoadLibraryExA(LPCSTR n, HANDLE f, DWORD fl);
HMODULE WINAPI hk_LoadLibraryExW(LPCWSTR n, HANDLE f, DWORD fl);
DWORD WINAPI hk_IcmpSendEcho(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD,
                             DWORD);
DWORD WINAPI hk_IcmpSendEcho2(HANDLE, HANDLE, FARPROC, PVOID, IPAddr, LPVOID, WORD,
                              PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
ULONG WINAPI hk_GetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved,
                                     PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);
ULONG WINAPI hk_GetAdaptersInfo(PIP_ADAPTER_INFO InfoBuffer, PULONG SizePointer);
FARPROC WINAPI hk_GetProcAddress(HMODULE m, LPCSTR n);

int WSAAPI hk_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to,
                     int tolen);
int WSAAPI hk_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from,
                       int *fromlen);
SOCKET WSAAPI hk_accept(SOCKET s, struct sockaddr *addr, int *addrlen);
int WSAAPI hk_WSASendTo(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD flags,
                        const struct sockaddr *to, int tolen, LPWSAOVERLAPPED ov,
                        LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
int WSAAPI hk_WSARecvFrom(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD recvd, LPDWORD flags,
                          struct sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED ov,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
int WSAAPI hk_connect(SOCKET s, const struct sockaddr *a, int l);
int WSAAPI hk_bind(SOCKET s, const struct sockaddr *a, int l);
int WSAAPI hk_WSAConnect(SOCKET s, const struct sockaddr *a, int l, LPWSABUF b1, LPWSABUF b2,
                         LPQOS q1, LPQOS q2);
int WSAAPI hk_getpeername(SOCKET s, struct sockaddr *a, int *l);
int WSAAPI hk_getsockname(SOCKET s, struct sockaddr *a, int *l);
int WSAAPI hk_closesocket(SOCKET s);
int WSAAPI hk_listen(SOCKET s, int backlog);
int WSAAPI hk_send(SOCKET s, const char *buf, int len, int flags);
int WSAAPI hk_recv(SOCKET s, char *buf, int len, int flags);
int WSAAPI hk_WSASend(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD sent, DWORD flags, LPWSAOVERLAPPED ov,
                      LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
int WSAAPI hk_WSARecv(SOCKET s, LPWSABUF b, DWORD nb, LPDWORD recvd, LPDWORD flags,
                      LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr);
int WSAAPI hk_ioctlsocket(SOCKET s, long cmd, u_long *argp);
int WSAAPI hk_shutdown(SOCKET s, int how);
int WSAAPI hk_getsockopt(SOCKET s, int level, int optname, char *optval, int *optlen);
int WSAAPI hk_select(int nfds, fd_set *r, fd_set *w, fd_set *x, const struct timeval *tmo);
int WSAAPI hk_WSAPoll(LPWSAPOLLFD fds, ULONG nfds, INT timeout);
int WSAAPI hk_WSAEventSelect(SOCKET s, WSAEVENT hEvent, long lNetworkEvents);
int WSAAPI hk_WSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject,
                                   LPWSANETWORKEVENTS lpNetworkEvents);
DWORD WSAAPI hk_WSAWaitForMultipleEvents(DWORD cEvents, const WSAEVENT *lphEvents, BOOL fWaitAll,
                                         DWORD dwTimeout, BOOL fAlertable);
WSAEVENT WSAAPI hk_WSACreateEvent(void);
BOOL WSAAPI hk_WSACloseEvent(WSAEVENT hEvent);

HK_INT int dt_icmp_pend_complete(unsigned id, unsigned seq, const unsigned char *data, size_t dlen,
                                 unsigned from_virt);
#endif
#endif
