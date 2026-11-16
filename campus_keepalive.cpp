// campus_keepalive.cpp
// 校园网保活进程（无窗口、只写日志）
// 行为照搬那个 bat：
//   每 20 秒 ping 一次网关 10.160.0.1（最多等 1000 毫秒）
//   失败则记一行日志，再 ping 一次 223.5.5.5
// 日志: 与 exe 同目录的 keepalive_log.txt（每次真正启动时清空重来）
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <share.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// 无控制台窗口
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/ENTRY:wmainCRTStartup")

// ---- 配置（跟 bat 里一致）----
static const char* GATEWAY_IP   = "10.160.0.1";   // bat 里 ping 的网关
static const char* FALLBACK_IP  = "223.5.5.5";    // 失败时备用
static const int   INTERVAL_SEC = 20;             // 每轮间隔
static const int   PING_TIMEOUT = 1000;           // 单次最多等 1000 毫秒
static const int   STATS_EVERY  = 90;             // 每 90 轮(30 分钟)记一条统计

static FILE* g_log = NULL;

static std::wstring GetExeDir()
{
    wchar_t buf[MAX_PATH] = { 0 };
    DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L".";
    std::wstring p(buf, n);
    size_t s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

// 每次真正启动都清空日志；重复启动的那一个不会调到这里
static void LogInit()
{
    std::wstring p = GetExeDir() + L"\\keepalive_log.txt";
    // _wfsopen + _SH_DENYWR: 允许别人读(记事本能打开看), 只禁止别人写
    // (_wfopen_s 是独占打开, 运行中日志会被锁死打不开)
    g_log = _wfsopen(p.c_str(), L"wb", _SH_DENYWR);
}

// 逐行加时间戳；空行不加
static void Log(const char* fmt, ...)
{
    char buf[2048];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!g_log) return;

    SYSTEMTIME st; GetLocalTime(&st);
    const char* p = buf;
    while (*p) {
        const char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p + 1) : strlen(p);
        if (!(len == 1 && *p == '\n'))
            fprintf(g_log, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
        fwrite(p, 1, len, g_log);
        if (!nl) break;
        p = nl + 1;
    }
    fflush(g_log);
}

// 崩溃时留证据；堆可能已坏，只用 snprintf + fwrite
static LONG WINAPI CrashHandler(EXCEPTION_POINTERS* ep)
{
    if (g_log) {
        DWORD code = (ep && ep->ExceptionRecord) ? ep->ExceptionRecord->ExceptionCode : 0;
        void* addr = (ep && ep->ExceptionRecord) ? ep->ExceptionRecord->ExceptionAddress : nullptr;
        char buf[512];
        int n = snprintf(buf, sizeof(buf),
            "\n[崩溃] 未处理异常! 异常代码=0x%08lX 出错地址=%p 线程=%lu\n",
            (unsigned long)code, addr, (unsigned long)GetCurrentThreadId());
        if (n > 0) {
            if (n > (int)sizeof(buf) - 1) n = (int)sizeof(buf) - 1;
            fwrite(buf, 1, (size_t)n, g_log);
            fflush(g_log);
        }
        fclose(g_log);
        g_log = NULL;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

// 一次 ping（ICMP 回显）。返回 true = 收到应答。
static bool PingOnce(const char* ip, int timeoutMs, DWORD* elapsedMs)
{
    IN_ADDR addr;
    memset(&addr, 0, sizeof(addr));
    if (InetPtonA(AF_INET, ip, &addr) != 1) return false;

    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return false;

    char payload[32];
    memset(payload, 'k', sizeof(payload));

    DWORD replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 16;
    std::vector<unsigned char> reply(replySize, 0);

    DWORD t0 = GetTickCount();
    DWORD n = IcmpSendEcho(h, addr.S_un.S_addr, payload, (WORD)sizeof(payload),
                           NULL, reply.data(), replySize, (DWORD)timeoutMs);
    DWORD t1 = GetTickCount();
    if (elapsedMs) *elapsedMs = t1 - t0;

    bool ok = false;
    if (n > 0) {
        PICMP_ECHO_REPLY p = (PICMP_ECHO_REPLY)reply.data();
        ok = (p->Status == IP_SUCCESS);
    }
    IcmpCloseHandle(h);
    return ok;
}

// 重复启动时: 追加一行说明, 不动正在运行那份的日志内容
static void NoteAlreadyRunning()
{
    std::wstring p = GetExeDir() + L"\\keepalive_log.txt";
    FILE* f = NULL;
    f = _wfsopen(p.c_str(), L"ab", _SH_DENYWR);
    if (!f) return;

    SYSTEMTIME st; GetLocalTime(&st);
    char line[256];
    int n = snprintf(line, sizeof(line),
                     "[%02d:%02d:%02d] 已在运行，本次启动直接退出\n",
                     st.wHour, st.wMinute, st.wSecond);
    if (n > 0) {
        if (n > (int)sizeof(line) - 1) n = (int)sizeof(line) - 1;
        fwrite(line, 1, (size_t)n, f);
    }
    fclose(f);
}

int wmain(int argc, wchar_t** argv)
{
    // 单实例：先判互斥量，再决定怎么开日志。
    // 上一个实例可能刚被控制台杀掉, 内核还没拆完 -> 退避重试, 避免"新实例误判已在运行而退出"
    // 三分状态要分清楚: 抢到 / 已存在 / 创建失败。
    // 把"创建失败"当成"抢到"会放两个实例进来, 且第二个连日志都写不了。
    HANDLE hMutex = NULL;
    bool already = false;
    for (int attempt = 0; attempt < 20; attempt++) {
        SetLastError(0);
        hMutex = CreateMutexW(NULL, TRUE, L"Global\\CampusKeepalive_10_160_0_1");
        if (!hMutex) {                        // 创建失败(典型: 权限不足)
            if (attempt < 19) Sleep(100);
            continue;
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS) break;   // 真的抢到了
        CloseHandle(hMutex); hMutex = NULL;   // 已存在: 关句柄退避再试(上一个可能刚被杀)
        already = true;
        if (attempt < 19) Sleep(100);
    }
    if (!hMutex) {
        if (already) NoteAlreadyRunning();    // 追加写, 不清掉正在运行那份的日志
        return 0;
    }

    LogInit();                        // 每次真正启动都清空重来, 日志不会无限涨
    SetUnhandledExceptionFilter(CrashHandler);

    Log("保活进程启动  PID=%lu  网关=%s  间隔=%d 秒  超时=%d 毫秒\n",
        (unsigned long)GetCurrentProcessId(), GATEWAY_IP, INTERVAL_SEC, PING_TIMEOUT);

    long okCnt = 0, failCnt = 0;
    long loop = 0;

    for (;;)
    {
        loop++;
        DWORD ms = 0;
        bool gwOk = PingOnce(GATEWAY_IP, PING_TIMEOUT, &ms);

        if (gwOk) {
            okCnt++;
            if (loop == 1)
                Log("首轮探测: %s 通（%lu 毫秒）\n", GATEWAY_IP, (unsigned long)ms);
        } else {
            failCnt++;
            Log("网关 %s 不通（等了 %lu 毫秒）-> 试公网 %s\n",
                GATEWAY_IP, (unsigned long)ms, FALLBACK_IP);

            DWORD ms2 = 0;
            bool fbOk = PingOnce(FALLBACK_IP, PING_TIMEOUT, &ms2);
            Log("  公网 %s : %s（%lu 毫秒）\n",
                FALLBACK_IP, fbOk ? "通" : "不通", (unsigned long)ms2);
        }

        if (loop % STATS_EVERY == 0) {
            Log("已运行 %ld 轮，成功 %ld 次，失败 %ld 次\n", loop, okCnt, failCnt);
        }

        Sleep(INTERVAL_SEC * 1000);
    }

    // 不会走到这里
    if (g_log) fclose(g_log);
    return 0;
}
