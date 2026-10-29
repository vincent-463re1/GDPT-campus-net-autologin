@echo off
chcp 936 >nul
title 卸载自启动 - 校园网自动登录

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo   [!] 需要管理员权限
    echo.
    echo  请: 右键本文件 -^> "以管理员身份运行" -^> UAC 点 "是"
    echo.
    pause
    exit /b 1
)

set "TN=校园网自动登录"
set "NCSIKEY=HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"

echo   卸载自启动: 校园网自动登录
echo.

echo  [1/2] 删除计划任务 "%TN%" ...
schtasks /Delete /TN "%TN%" /F
if %errorLevel% equ 0 (
    echo        [OK] 已删除, 不再自动登录
) else (
    echo        [提示] 任务不存在, 或删除失败
)
echo.

echo  [2/2] 恢复 NCSI 门户探测 ^(EnableActiveProbing = 1^) ...
reg add "%NCSIKEY%" /v EnableActiveProbing /t REG_DWORD /d 1 /f >nul 2>&1
if %errorLevel% equ 0 (
    echo        [OK] 已恢复 - 系统重新启用门户探测
) else (
    echo        [失败] 注册表写入被拒 ^(可能被 360 拦截^)
)
echo.
echo   卸载完成。建议重启电脑让 NCSI 设置生效。
echo.
pause