#include "pch.h"
#include "misc.h"
#include <winternl.h>

#pragma comment(lib, "Psapi.lib")


// 获取当前控制台的文本属性
WORD getConsoleCurrentColor()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	return consoleInfo.wAttributes; // 返回当前的文本属性
}

// 设置控制台的文本属性
void setConsoleColor(WORD color)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, color);
}

BOOL IsWow64()
{
	BOOL bIsWow64 = FALSE;
	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

	static LPFN_ISWOW64PROCESS fnIsWow64Process = NULL;

	if (!fnIsWow64Process)
		fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
			GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		{
			//handle error
		}
	}
	return bIsWow64;
}

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}
	return TRUE;
}


BOOL IsWindowsVersionOrGreater(WORD wMajorVersion, WORD wMinorVersion, WORD wServicePackMajor)
{
	OSVERSIONINFOEXW osvi = {};
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			VerSetConditionMask(
				0, VER_MAJORVERSION, VER_GREATER_EQUAL),
			VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != FALSE;
}

BOOL IsWindowsVistaOrGreater()
{
	return IsWindowsVersionOrGreater(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0);
}

BOOL IsElevated() {

	if (!IsWindowsVistaOrGreater()) {
		return TRUE;
	}

	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = !!Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

PNtQuerySystemInformation GetNtQuerySystemInformation() {
	static PNtQuerySystemInformation p = NULL;
	if (p) return p;
	HMODULE hNtDll = GetModuleHandle(_T("ntdll.dll"));
	if (!hNtDll) {
		return nullptr;
	}
	p = (PNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
	return p;
}
std::wstring ResolveDevicePath(const std::wstring& devicePath) {
	std::vector<wchar_t> driveLetters(MAX_PATH);

	if (GetLogicalDriveStringsW(MAX_PATH, driveLetters.data()) == 0) {
		return devicePath;
	}

	for (wchar_t* driveLetter = driveLetters.data(); *driveLetter; driveLetter += 4) {
		std::wstring currentDrive(driveLetter);
		WCHAR currentDevicePath[MAX_PATH] = { 0 };

		if (QueryDosDeviceW(currentDrive.substr(0, 2).c_str(), currentDevicePath, MAX_PATH) == 0) {
			continue;
		}
		if (devicePath.find(currentDevicePath) == 0) {
			return currentDrive.substr(0, 2) + devicePath.substr(wcslen(currentDevicePath));
		}
	}

	return devicePath;
}
BOOL GetProcessPathByPid1(DWORD dwPID, LPTSTR lpszBuf, int nBufSize) {
	// private
	typedef struct _SYSTEM_PROCESS_ID_INFORMATION
	{
		HANDLE ProcessId;
		UNICODE_STRING ImageName;
	} SYSTEM_PROCESS_ID_INFORMATION, * PSYSTEM_PROCESS_ID_INFORMATION;
	const int _SystemProcessIdInformation = 88;

	NTSTATUS status;
	PVOID buffer = nullptr;
	ULONG bufferSize = 0x100;
	SYSTEM_PROCESS_ID_INFORMATION processIdInfo = {};

	buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
	if (!buffer) {
		return FALSE;
	}

	processIdInfo.ProcessId = (HANDLE)(ULONG_PTR)dwPID;
	processIdInfo.ImageName.Length = 0;
	processIdInfo.ImageName.MaximumLength = (USHORT)bufferSize;
	processIdInfo.ImageName.Buffer = (PWSTR)buffer;

	status = GetNtQuerySystemInformation()(
		(SYSTEM_INFORMATION_CLASS)_SystemProcessIdInformation,
		&processIdInfo,
		sizeof(SYSTEM_PROCESS_ID_INFORMATION),
		nullptr
		);

	if (status == (NTSTATUS)0xC0000004L) { //STATUS_INFO_LENGTH_MISMATCH
		HeapFree(GetProcessHeap(), 0, buffer);
		bufferSize = processIdInfo.ImageName.MaximumLength;
		buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
		if (!buffer) {
			return FALSE;
		}

		processIdInfo.ImageName.Buffer = (PWSTR)buffer;
		status = GetNtQuerySystemInformation()(
			(SYSTEM_INFORMATION_CLASS)_SystemProcessIdInformation,
			&processIdInfo,
			sizeof(SYSTEM_PROCESS_ID_INFORMATION),
			nullptr
			);
	}

	if (!NT_SUCCESS(status)) {
		HeapFree(GetProcessHeap(), 0, buffer);
		return FALSE;
	}


	std::wstring imagePath = std::wstring(processIdInfo.ImageName.Buffer, processIdInfo.ImageName.Length / sizeof(WCHAR));
	HeapFree(GetProcessHeap(), 0, buffer);

	if (imagePath.empty()) {
		return FALSE;
	}

	imagePath = ResolveDevicePath(imagePath);

	if (nBufSize < (int)(imagePath.size() + 1)) {
		return FALSE;
	}

#ifdef UNICODE
	wcscpy_s(lpszBuf, nBufSize, imagePath.c_str());
#else
	WideCharToMultiByte(CP_ACP, 0, imagePath.c_str(), -1, lpszBuf, nBufSize, nullptr, nullptr);
#endif

	return lpszBuf[0] != '\0';
}

BOOL GetProcessPathByPid2(DWORD dwPID, LPTSTR lpszBuf, int nBufSize)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32W me32;

RETRY:

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_BAD_LENGTH)
			goto RETRY;
		return(FALSE);
	}

	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32FirstW(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return(FALSE);
	}

	wcsncpy_s(lpszBuf, nBufSize, me32.szExePath, nBufSize);
	CloseHandle(hModuleSnap);
	return lpszBuf[0] != '\0';
}

BOOL GetProcessPathByPid3(DWORD dwPID, LPTSTR lpszBuf, int nBufSize)
{
	DWORD n = 0;
	HANDLE hProc;
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
	if (!hProc)
		hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
	if (hProc) {
		n = GetModuleFileNameEx(hProc, NULL, lpszBuf, nBufSize);
		CloseHandle(hProc);
	}
	return n > 0;
}

BOOL GetProcessPathByPid(DWORD dwPID, LPTSTR lpszBuf, int nBufSize)
{
	return GetProcessPathByPid3(dwPID, lpszBuf, nBufSize)
		|| GetProcessPathByPid2(dwPID, lpszBuf, nBufSize)
		|| GetProcessPathByPid1(dwPID, lpszBuf, nBufSize);
}

BOOL GetProcessList(std::list<PROCESSENTRY32>& ls)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return(FALSE);
	}

	do
	{
		ls.push_back(pe32);

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);
}
