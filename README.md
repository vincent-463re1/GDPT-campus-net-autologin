# 校园网自动登录 (Campus Net Auto-Login)

锐捷 ePortal 校园网的纯 HTTP 自动认证工具，Windows / C++，无浏览器、无窗口、秒级完成。

## 组成

| 文件 | 说明 |
|------|------|
| `httplogin.cpp` | 主程序：检测网络状态，掉线时自动登录（GUI 子系统，无窗口）|
| `campus_ctl.cpp` | 控制台工具：1 上线 / 2 下线 / 3 重新登录 / 4 退出 |
| `install_autostart.bat` | 安装：关 NCSI 探测 + 创建登录触发的计划任务 + 桌面快捷方式 |
| `uninstall_autostart.bat` | 卸载：删任务 + 恢复 NCSI |

## 工作原理

直接调门户的 HTTP 接口，不模拟点击网页。

1. 读同目录 `auth.txt`（第 1 行账号、第 2 行密码）
2. 判断网络级别（WinRT `GetNetworkConnectivityLevel`）
3. 探针：`9.9.9.9` 的 TCP 连接
   - 不可达 -> 已联网，退出（再用 `www.baidu.com` 复检）
   - 可达 -> 被网关劫持
4. 请求 `http://9.9.9.9/` 拿门户地址（劫持返回 200 + JS 跳转，不是 302）
5. 从 JS 提取 `location.href` -> 门户 URL + queryString
6. 门户地址自适应（`ExtractOrigin`），兜底 `10.110.141.3`
7. POST `InterFace.do?method=login`
8. 检查响应 `result` 是否为 `success`

登录成功后全程只需 2 次 HTTP 请求，1~2 秒完成。

## 关键实现细节

- **无窗口**：PE 子系统设为 Windows GUI，失败时才 `AllocConsole` 弹提示
- **日志**：`_wfopen_s(..., L"wb")` + `fwrite`，绝不用 `ccs=UTF-8` + `fprintf`（遇中文会 `__fastfail` 崩溃，退出码 `0xC0000409`）
- **便携**：`auth.txt` 和日志都定位到 exe 自身目录（`GetModuleFileNameW`），整个文件夹可搬走
- **崩溃可见**：`SetUnhandledExceptionFilter` 把异常码/地址写进日志
- **超时兜底**：独立线程 watchdog 强制结束，避免卡死

## 编译

需要 MSVC + Windows SDK + C++/WinRT 头文件。

```bat
cl /nologo /std:c++20 /EHsc /O2 /utf-8 httplogin.cpp ^
   /I "<SDK目录>\Include\<版本>\cppwinrt" /Fe:httplogin.exe

cl /nologo /std:c++17 /EHsc /O2 /utf-8 campus_ctl.cpp /Fe:校园网控制台.exe
```

`httplogin.cpp` 必须用 `/std:c++20`（C++/WinRT 依赖 `<coroutine>`，C++17 会 C2338 报错）。

## 使用

1. 编译出 `httplogin.exe` / `校园网控制台.exe`
2. 同目录放 `auth.txt`（第 1 行学号，第 2 行密码）
3. 右键 `install_autostart.bat` -> 以管理员身份运行
4. 之后每次登录 Windows 自动认证

## 注意事项

- `auth.txt` 含明文密码，**不要提交到仓库、不要连同程序一起外发**（`.gitignore` 已排除）
- 首次跑 bat 时杀毒软件可能拦截（创建计划任务/快捷方式），选允许
- 门户地址代码里有兜底 `10.110.141.3`，换校区可能要调整
- 校园网内可能访问不了 GitHub，用手机热点或代理

## 环境实测数据（某高校有线校园网）

| 地址 | 联网时 | 掉线时 |
|------|--------|--------|
| `9.9.9.9` | http=000（4 秒超时）| http=200 + JS 跳转（0.01 秒）**唯一可用探针** |
| `223.5.5.5` | http=404 | http=200 —— 两种状态都可达，**不能当探针** |
| `114.114.114.114` | http=000 | http=000 —— 无信息 |
| `www.baidu.com` | http=200 | http=000 —— **可作复检** |

结论：探针要选「掉线时被劫持、联网时不通」的地址；「联网时响应快」是错误的判断标准。
