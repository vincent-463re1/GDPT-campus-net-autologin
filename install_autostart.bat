@echo off
chcp 936 >nul
title 安装自启动 - 校园网自动登录

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

set "EXE=%~dp0httplogin.exe"
set "DIR=%~dp0"
set "NCSIKEY=HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet"

echo   安装自启动: 校园网自动登录
echo.
echo  程序: %EXE%
echo  触发: 登录时 (任何用户)
echo  条件: 已关闭电池限制
echo.

if not exist "%EXE%" (
    echo  [错误] 本目录下没找到 httplogin.exe
    echo.
    pause
    exit /b 1
)

echo  [1/3] 关闭 NCSI 门户探测 (防止系统自动弹门户页)...
reg add "%NCSIKEY%" /v EnableActiveProbing /t REG_DWORD /d 0 /f >nul 2>&1
if %errorLevel% equ 0 (
    echo        [OK] EnableActiveProbing = 0
) else (
    echo        [失败] 注册表写入被拒
)
echo.

echo  [2/3] 创建计划任务...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$e='%EXE%'; $d='%DIR%'; try { $a=New-ScheduledTaskAction -Execute $e -WorkingDirectory $d; $c=Get-CimClass -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskLogonTrigger; $t=New-CimInstance -CimClass $c -ClientOnly -Property @{Enabled=$true}; $s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew; Register-ScheduledTask -TaskName '校园网自动登录' -Action $a -Trigger $t -Settings $s -Force -ErrorAction Stop | Out-Null; Write-Host ''; Write-Host '       [成功] 计划任务已创建!' -ForegroundColor Green; Write-Host '              查看: Win+R -> taskschd.msc' } catch { Write-Host ''; Write-Host ('       [失败] ' + $_.Exception.Message) -ForegroundColor Red }"

echo.

echo  [3/3] 创建桌面快捷方式 (校园网控制台)...
echo        提示: 若杀毒软件(360等)弹窗拦截, 请点 "允许"/"通过"
echo              否则桌面不会出现快捷方式
set "CTL=%DIR%校园网控制台.exe"
if exist "%CTL%" (
powershell -NoProfile -ExecutionPolicy Bypass -Command "$w=New-Object -ComObject WScript.Shell; $desk=[Environment]::GetFolderPath('Desktop'); $lnk=$w.CreateShortcut($desk+'\校园网控制台.lnk'); $lnk.TargetPath='%CTL%'; $lnk.WorkingDirectory='%DIR%'; $lnk.IconLocation='%CTL%,0'; $lnk.Save(); Write-Host '        [OK] 已创建: 桌面\校园网控制台.lnk' -ForegroundColor Green"
) else (
    echo        [跳过] 本目录没找到 校园网控制台.exe
)
echo.
pause