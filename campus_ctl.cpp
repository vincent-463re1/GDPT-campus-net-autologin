// campus_ctl.cpp —— 校园网 上/下线 控制台工具
//   1 = 上线      (调用 httplogin.exe)
//   2 = 下线      (调门户 InterFace.do?method=logout)
//   3 = 重新登录  (下线 -> 等 1 秒 -> 上线)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <conio.h>
#include <cstdio>
#include <locale.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "user32.lib")

// 门户地址 与 上线程序路径
static const wchar_t* PORTAL_HOST = L"10.110.141.3";
static const wchar_t* LOGIN_EXE   = L"D:\\校园网\\httplogin.exe";
static const wchar_t* LOGIN_EXE2  = L"httplogin.exe";   // 同目录兜底

// UTF-8(std::string) -> 宽字符, 供 wprintf 输出
static std::wstring U2W(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), NULL, 0);
    if (n <= 0) return L"";
    std::wstring w((size_t)n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

// ---------------- HTTP 小工具 ----------------
struct Resp { int status = 0; std::string body; std::wstring location; DWORD err = 0; };

static bool HttpReq(const std::wstring& url, const wchar_t* method,
                    const std::string& body, bool follow, Resp& r)
{
    r = Resp();
    std::wstring u = url, host, path;
    INTERNET_PORT port = 80;
    if (u.rfind(L"http://", 0) == 0) { u = u.substr(7); port = 80; }
    else if (u.rfind(L"https://", 0) == 0) { u = u.substr(8); port = 443; }
    else return false;
    size_t slash = u.find(L'/');
    host = (slash == std::wstring::npos) ? u : u.substr(0, slash);
    path = (slash == std::wstring::npos) ? L"/" : u.substr(slash);

    HINTERNET hS = WinHttpOpen(L"campus_ctl/1", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hS) return false;
    WinHttpSetTimeouts(hS, 2000, 2000, 2000, 4000);
    if (!follow) {
        DWORD pol = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
        WinHttpSetOption(hS, WINHTTP_OPTION_REDIRECT_POLICY, &pol, sizeof(pol));
    }
    HINTERNET hC = WinHttpConnect(hS, host.c_str(), port, 0);
    if (!hC) { r.err = GetLastError(); WinHttpCloseHandle(hS); return false; }
    HINTERNET hR = WinHttpOpenRequest(hC, method, path.c_str(), NULL, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return false; }

    std::wstring hdr;
    if (!body.empty()) hdr += L"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n";

    BOOL ok = WinHttpSendRequest(hR,
        hdr.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdr.c_str(),
        hdr.empty() ? 0 : (DWORD)-1L,
        body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
        (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hR, NULL);
    if (!ok) r.err = GetLastError();

    if (ok) {
        DWORD st = 0, len = sizeof(st);
        WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &st, &len, WINHTTP_NO_HEADER_INDEX);
        r.status = (int)st;
        wchar_t lbuf[2048]; DWORD n = sizeof(lbuf);
        if (WinHttpQueryHeaders(hR, WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                                lbuf, &n, WINHTTP_NO_HEADER_INDEX))
            r.location = lbuf;
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
            std::vector<char> b(avail); DWORD rd = 0;
            if (!WinHttpReadData(hR, b.data(), avail, &rd)) break;
            r.body.append(b.data(), rd);
            if (r.body.size() > 64 * 1024) break;
        }
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    return ok != FALSE;
}

static std::string JsonStr(const std::string& j, const char* key)
{
    std::string pat = std::string("\"") + key + "\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return "";
    p = j.find(':', p + pat.size());
    if (p == std::string::npos) return "";
    p = j.find('"', p);
    if (p == std::string::npos) return "";
    size_t e = j.find('"', p + 1);
    if (e == std::string::npos) return "";
    return j.substr(p + 1, e - p - 1);
}

static std::string ExtractUserIndexStr(const std::string& s)
{
    size_t p = s.find("userIndex=");
    if (p == std::string::npos) return "";
    p += 10;
    size_t e = s.find_first_of("&#\"' \r\n<>", p);
    return s.substr(p, (e == std::string::npos) ? std::string::npos : e - p);
}

static std::string W2A_ascii(const std::wstring& w)
{
    std::string s; s.reserve(w.size());
    for (wchar_t c : w) s += (char)(c & 0xFF);
    return s;
}
static std::wstring A2W_ascii(const std::string& a)
{
    std::wstring w; w.reserve(a.size());
    for (char c : a) w += (wchar_t)(unsigned char)c;
    return w;
}

// ---------------- 取 userIndex ----------------
static std::string GetUserIndex()
{
    // 手动逐跳跟随 (WinHttp 自动跟随后就拿不到中间那跳的 Location 了, 而 userIndex 正在其中):
    //   GET /  ->  302 Location: /eportal/redirectortosuccess.jsp
    //                 -> 302 Location: /eportal/success.jsp?userIndex=xxxx
    Resp r;
    std::wstring url = L"http://10.110.141.3/";
    for (int hop = 0; hop < 6; hop++) {
        if (!HttpReq(url, L"GET", "", false, r)) return "";
        std::string loc = W2A_ascii(r.location);
        std::string ui = ExtractUserIndexStr(loc);
        if (!ui.empty()) return ui;
        ui = ExtractUserIndexStr(r.body);
        if (!ui.empty()) return ui;
        if (loc.empty()) return "";
        url = (loc.rfind("http", 0) == 0) ? A2W_ascii(loc)
                                          : A2W_ascii("http://10.110.141.3" + loc);
    }
    return "";
}

// 按键读取: 直接用控制台 API, 不依赖 CRT 的 _getch/_kbhit
// (_getch 在某些控制台状态下会退化成"等 Enter", 且按键被回显 -> 看起来像"按了没反应")
// ---------- 按键读取 ----------
// 不用 _getch / ReadConsoleInput: 中文输入法开启时, 按键会被输入法先拿去组词
// (出现候选框), 控制台层根本收不到 -> 表现为"按了没反应"。
// GetAsyncKeyState 读的是物理键状态, 输入法拦不住。
static void InitConsoleInput()
{
    HANDLE hi = GetStdHandle(STD_INPUT_HANDLE);
    if (!hi || hi == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (GetConsoleMode(hi, &mode)) {
        mode &= ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        SetConsoleMode(hi, mode);
    }
    // 清掉残留的按下状态
    for (int vk = 8; vk < 256; vk++) GetAsyncKeyState(vk);
}

// 把一个虚拟键码转成可打印字符 (拿不到就返回 1 表示"任意键")
static int VkToChar(int vk)
{
    if (vk >= '0' && vk <= '9')               return vk;
    if (vk >= 'A' && vk <= 'Z')               return vk;
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) return '0' + (vk - VK_NUMPAD0);
    return 1;                                  // 其它任意键
}

static bool IsModifier(int vk)
{
    return vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
           vk == VK_LSHIFT || vk == VK_RSHIFT || vk == VK_LCONTROL ||
           vk == VK_RCONTROL || vk == VK_LMENU || vk == VK_RMENU;
}

// 扫一遍键盘。
// 注意位判断: 0x8000 = 当前按住; 0x0001 = 自上次调用以来按过(即使已松开)。
// 快速点按(几毫秒就松开)只会留下 0x0001, 只查 0x8000 会漏掉 -> 这就是之前"按了没反应"的原因。
static int ScanKey()
{
    for (int vk = 8; vk < 256; vk++) {
        if (IsModifier(vk)) continue;
        SHORT st = GetAsyncKeyState(vk);
        if (st & 0x8001) {
            while (GetAsyncKeyState(vk) & 0x8000) Sleep(10);   // 还按着就等它松开
            return VkToChar(vk);
        }
    }
    return 0;
}

// 清掉历史标志位 (调用 GetAsyncKeyState 本身就会重置 0x0001)
static void FlushKeyState()
{
    for (int vk = 8; vk < 256; vk++) GetAsyncKeyState(vk);
}

// 阻塞取键
static int WaitKey()
{
    FlushKeyState();
    for (;;) {
        int k = ScanKey();
        if (k != 0) return k;
        Sleep(25);
    }
}

// 非阻塞取键 (执行期间查 0 用)
static int PollKey()
{
    return ScanKey();
}
// 等待子进程结束; 期间按 0 可强制退出 (中止子进程并立即结束本程序)
static void WaitChildOrCancel(HANDLE hProc)
{
    for (int i = 0; i < 300; i++) {          // 最多 30 秒
        DWORD w = WaitForSingleObject(hProc, 100);
        if (w == WAIT_OBJECT_0) return;      // 子进程已结束
        int k = PollKey();
        if (k == '0') {
            wprintf(L"\n[强制退出] 按了 0, 中止并退出\n");
            TerminateProcess(hProc, 0);
            ExitProcess(0);
        }
    }
    TerminateProcess(hProc, 0);              // 超时兜底
}

// ---------------- 上线 ----------------
static bool DoLogin()
{
    // 优先用"本程序同目录"的 httplogin.exe (整个文件夹搬走也能用),
    // 找不到再退回默认路径。
    std::wstring exePath;
    {
        wchar_t self[MAX_PATH] = {0};
        if (GetModuleFileNameW(NULL, self, MAX_PATH) > 0) {
            std::wstring p(self);
            size_t s = p.find_last_of(L"\\/");
            std::wstring dir = (s == std::wstring::npos) ? L"." : p.substr(0, s);
            std::wstring alt = dir + L"\\httplogin.exe";
            if (GetFileAttributesW(alt.c_str()) != INVALID_FILE_ATTRIBUTES)
                exePath = alt;
        }
    }
    if (exePath.empty() && GetFileAttributesW(LOGIN_EXE) != INVALID_FILE_ATTRIBUTES)
        exePath = LOGIN_EXE;

    if (exePath.empty()) {
        wprintf(L"  [错误] 找不到 httplogin.exe\n");
        wprintf(L"         找过: 本程序同目录 / %ls\n", LOGIN_EXE);
        return false;
    }

    wprintf(L"  [上线] 使用: %ls\n", exePath.c_str());

    STARTUPINFOW si = {0}; PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    std::wstring cmd = L"\"" + exePath + L"\"";
    if (!CreateProcessW(exePath.c_str(), &cmd[0], NULL, NULL, FALSE, 0,
                        NULL, NULL, &si, &pi)) {
        wprintf(L"  [错误] 启动失败 (err=%lu)\n", GetLastError());
        return false;
    }
    WaitChildOrCancel(pi.hProcess);
    DWORD code = 0; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    wprintf(L"  [上线] 完成 (退出码=%lu)\n", code);
    return (code == 0);
}

// ---------------- 下线 ----------------
static bool DoLogout()
{
    wprintf(L"  [下线] 获取 userIndex ...\n");
    std::string ui = GetUserIndex();
    if (ui.empty()) {
        wprintf(L"  [下线] 未取到 userIndex, 可能本来就不在线\n");
        return false;
    }
    wprintf(L"  [下线] userIndex = %hs\n", ui.c_str());

    std::string body = "userIndex=" + ui;
    Resp r;
    if (!HttpReq(L"http://10.110.141.3/eportal/InterFace.do?method=logout", L"POST", body, false, r)) {
        wprintf(L"  [下线] 请求失败 (err=%lu)\n", r.err);
        return false;
    }
    wprintf(L"  [下线] 响应: %ls\n", U2W(r.body.empty() ? "" : r.body).c_str());
    std::string res = JsonStr(r.body, "result");
    std::string msg = JsonStr(r.body, "message");
    if (res == "success") {
        wprintf(L"  [下线] 成功! %ls\n", U2W(msg).c_str());
        return true;
    }
    wprintf(L"  [下线] 未成功 (result=%hs)\n", res.empty() ? "?" : res.c_str());
    return false;
}

// ---------------- 菜单 ----------------
int main(int argc, char** argv)
{
    setlocale(LC_ALL, "");          // 关键: 不设的话 wprintf 在 "C" locale 下转不出中文, 会输出空
    SetConsoleOutputCP(936);
    SetConsoleTitleW(L"校园网 上线/下线");
    InitConsoleInput();            // 关行输入/回显, 保证按键即时生效

    // 支持命令行直接执行: campus_ctl.exe 1|2|3
    if (argc > 1) {
        switch (argv[1][0]) {
            case '1': DoLogin();  return 0;
            case '2': DoLogout(); return 0;
            case '3': DoLogout(); Sleep(1000); DoLogin(); return 0;
            default:  wprintf(L"用法: 校园网控制台.exe [1|2|3]   1=上线 2=下线 3=重新登录\n"); return 1;
        }
    }

    wprintf(L"校园网 上线/下线\n\n");
    wprintf(L"  1  上线\n");
    wprintf(L"  2  下线\n");
    wprintf(L"  3  重新登录\n");
    wprintf(L"  4  退出\n\n");

    // 只接受 1/2/3/4; 其它按键一律忽略(不动作也不回显), 继续等待
    int c = 0;
    for (;;) {
        c = WaitKey();
        if (c == '1' || c == '2' || c == '3' || c == '4') break;
    }
    wprintf(L"%c\n\n", c);

    if (c == '4') return 0;              // 4 -> 直接退出

    if (c == '1') {
        DoLogin();
    } else if (c == '2') {
        DoLogout();
    } else if (c == '3') {
        wprintf(L"[重登] 先下线 ...\n");
        DoLogout();
        wprintf(L"[重登] 等 1 秒 ...\n");
        Sleep(1000);
        wprintf(L"[重登] 再上线 ...\n");
        DoLogin();
    }

    Sleep(1000);                         // 结果保持 1 秒, 自动退出(无需按键)
    return 0;
}