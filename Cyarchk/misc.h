#pragma once

#include <list>
#include <string>
#include <tlhelp32.h>

WORD getConsoleCurrentColor();
void setConsoleColor(WORD color);
BOOL IsWow64();
BOOL EnableDebugPrivilege();
BOOL IsWindowsVistaOrGreater();
BOOL IsElevated();
BOOL GetProcessPathByPid(DWORD dwPID, LPTSTR lpszBuf, int nBufSize);
BOOL GetProcessList(std::list<PROCESSENTRY32>& ls);
