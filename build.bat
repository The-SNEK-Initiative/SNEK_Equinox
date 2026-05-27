@echo off
setlocal enabledelayedexpansion

call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

set OUT=.\bin
set OBJ=.\obj

if not exist %OUT% mkdir %OUT%
if not exist %OBJ% mkdir %OBJ%

set CC=cl.exe
set LD=link.exe
set CFLAGS=/nologo /W3 /WX- /O2 /EHsc /D_CRT_SECURE_NO_WARNINGS
set LFLAGS=/SUBSYSTEM:CONSOLE /MACHINE:X64 /NOLOGO

echo Building Equinox...
%CC% %CFLAGS% /c Equinox.cpp /Fo%OBJ%\Equinox.obj
if errorlevel 1 goto end
%LD% %LFLAGS% %OBJ%\Equinox.obj kernel32.lib ntdll.lib advapi32.lib /OUT:%OUT%\Equinox.exe
echo Equinox OK

echo Building spoof...
%CC% %CFLAGS% /c spoof.cpp /Fo%OBJ%\spoof.obj
if errorlevel 1 goto end
%LD% %LFLAGS% %OBJ%\spoof.obj kernel32.lib advapi32.lib /OUT:%OUT%\spoof.exe
echo spoof OK

echo Building vers...
%CC% %CFLAGS% /c vers.cpp /Fo%OBJ%\vers.obj
if errorlevel 1 goto end
%LD% %LFLAGS% %OBJ%\vers.obj kernel32.lib advapi32.lib /OUT:%OUT%\vers.exe
echo vers OK

echo Building run...
%CC% %CFLAGS% /c run.cpp /Fo%OBJ%\run.obj
if errorlevel 1 goto end
%LD% %LFLAGS% %OBJ%\run.obj kernel32.lib /OUT:%OUT%\run.exe
echo run OK

echo.
echo Build complete - bin\ has: Equinox.exe spoof.exe vers.exe run.exe

:end
