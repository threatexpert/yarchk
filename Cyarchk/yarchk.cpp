#include "pch.h"
#include <sstream>
#include <list>
#include <string>
#include <windows.h>
#include <algorithm>
#include <iterator>
#include <filesystem>
#include <time.h>
#include <vector>
#include <sys/stat.h>
#include <direct.h>
#include <fstream>
#include <unordered_map>
#include "SubProcess.h"
#include "misc.h"

namespace fs = std::filesystem;
using namespace std;

int gnCTRLC = 0;
CString gYaraApp;
BOOL bIsElevated = FALSE;


class YaraApp : public SubProcess
{
public:
	DWORD m_proc_id;
	CString m_target_proc_name;
	CString m_target_proc_fullpath;
	DWORD m_last_drain;
	std::string stdout_str;
	std::string stderr_str;
	YaraApp(DWORD dwPid, LPCTSTR lpszProcName, LPCTSTR lpszProcFullPath) {
		m_proc_id = dwPid;
		if (lpszProcName)
			m_target_proc_name = lpszProcName;
		if (lpszProcFullPath)
			m_target_proc_fullpath = lpszProcFullPath;
		m_last_drain = GetTickCount();
	}
	~YaraApp() {

	}

	void drain_output(HANDLE &hPipe, std::string& out) {
		DWORD dwAvail = 0;
		char buf[1024];
		unsigned int nread;

		if (PeekNamedPipe(hPipe, NULL, 0, NULL, &dwAvail, NULL)) {
			while (dwAvail > 0) {
				nread = min(dwAvail, sizeof(buf));
				if (ReadPipe(hPipe, buf, &nread, 0) > 0 && nread > 0) {
					out.append(buf, nread);
					dwAvail -= nread;
				}
				else {
					break;
				}
			}
		}
	}

	void try_drain_output(DWORD interval_ms = 1000) {
		if (GetTickCount() - m_last_drain >= interval_ms)
		{
			drain_output(_hChildStd_OUT_Rd, stdout_str);
			if (_hChildStd_ERR_Rd) {
				drain_output(_hChildStd_ERR_Rd, stderr_str);
			}
			m_last_drain = GetTickCount();
		}

	}

};

class YaraAppMgr
{
public:
	std::list<YaraApp*> m_tasks_doing;
	std::list<YaraApp*> m_tasks_done;

	YaraAppMgr() {

	}
	~YaraAppMgr() {
		clean();
	}

	void clean() {
		for (std::list<YaraApp*>::iterator it = m_tasks_doing.begin(); it != m_tasks_doing.end(); it++) {
			delete *it;
		}
		for (std::list<YaraApp*>::iterator it = m_tasks_done.begin(); it != m_tasks_done.end(); it++) {
			delete* it;
		}
		m_tasks_doing.clear();
		m_tasks_done.clear();
	}

	DWORD get_proc_count() {
		return (DWORD)m_tasks_doing.size();
	}

	int check_dead(std::list<YaraApp*> *justdone = NULL) {
		DWORD dwEC;
		int d = 0;
		for (std::list<YaraApp*>::iterator it = m_tasks_doing.begin(); it != m_tasks_doing.end(); ) {
			YaraApp* app = *it;
			if (app->WaitForProcessExitCode2(0, &dwEC) != 0){
				app->try_drain_output(0);
				m_tasks_done.push_back(app);
				if (justdone) {
					justdone->push_back(app);
				}
				it = m_tasks_doing.erase(it);
				d++;
			}
			else
			{
				app->try_drain_output();
				it++;
			}
		}
		return d;
	}

	void killall() {
		for (std::list<YaraApp*>::iterator it = m_tasks_doing.begin(); it != m_tasks_doing.end(); it++) {
			(*it)->Close();
		}
	}

	BOOL run_yara(const std::list<CString> &rules, bool compiled, DWORD dwPid, LPCTSTR lpszProcName, LPCTSTR lpszProcPath) {
		CString strCommand;
		CString strItem;
		if (compiled) {
			strCommand.Format(_T("\"%s\" -C "), (LPCTSTR)gYaraApp);
		}
		else {
			strCommand.Format(_T("\"%s\" "), (LPCTSTR)gYaraApp);
		}
		for (auto & s: rules) {
			strItem.Format(_T("\"%s\" "), (LPCTSTR)s);
			strCommand += strItem;
		}
		strItem.Format(_T("%d"), dwPid);
		strCommand += strItem;

		YaraApp* app = new YaraApp(dwPid, lpszProcName, lpszProcPath);
		m_tasks_doing.push_back(app);
		if (!app->CreateChild(strCommand, SubProcess::StderrAlone)) {
			m_tasks_doing.pop_back();
			delete app;
			return FALSE;
		}

		return TRUE;
	}

};

BOOL CtrlHandler(DWORD fdwCtrlType)
{
	switch (fdwCtrlType)
	{
		// Handle the CTRL-C signal. 
	case CTRL_C_EVENT:
		printf("Ctrl-C pressed\r\n");
		gnCTRLC++;
		return(TRUE);

	default:
		return FALSE;
	}
}

BOOL LocateYaraExe(LPTSTR lpszBuf, int bufsize)
{
	TCHAR szCurrDir[MAX_PATH];
	lpszBuf[0] = '\0';

	GetEnvironmentVariable(_T("YARAAPP"), lpszBuf, bufsize);
	if (lpszBuf[0] != '\0' && PathFileExists(lpszBuf)) {
		return TRUE;
	}

	GetModuleFileName(NULL, szCurrDir, MAX_PATH);
	*PathFindFileName(szCurrDir) = '\0';

	*lpszBuf = 0;
	_tcscat_s(lpszBuf, bufsize, szCurrDir);
	if (IsWow64()) {
		_tcscat_s(lpszBuf, bufsize, _T("\\yara\\yara64.exe"));
	}
	else {
		_tcscat_s(lpszBuf, bufsize, _T("\\yara\\yara32.exe"));
	}
	if (PathFileExists(lpszBuf)) {
		return TRUE;
	}

	return FALSE;
}

void traverse_yar(const CString& path, std::vector<CString>& files) {
	WIN32_FIND_DATAW FindFileData;
	HANDLE hFind;

	CString pattern;
	if (path.GetLength() > 0)
		pattern = path + L"\\*";
	else
		pattern = L"*";

	hFind = FindFirstFileW(pattern, &FindFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			CString item_path;
			if (path.GetLength() > 0)
				item_path = path + L"\\" + FindFileData.cFileName;
			else
				item_path = FindFileData.cFileName;
			
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (wcscmp(FindFileData.cFileName, L".") && wcscmp(FindFileData.cFileName, L"..")) {
					traverse_yar(item_path, files);
				}
			}
			else {
				if (!item_path.Right(4).CompareNoCase(L".yar") || !item_path.Right(5).CompareNoCase(L".yara")) {
					files.push_back(item_path);
				}
			}
		} while (FindNextFile(hFind, &FindFileData));
		FindClose(hFind);
	}
}

BOOL merge_files(std::vector<CString>& files, const char* splitter, LPCTSTR lpszOutput)
{
	std::ofstream outputFile(lpszOutput, std::ios::binary);
	if (!outputFile.is_open())
	{
		_ftprintf(stderr, _T("Failed to open output file: %s\n"), lpszOutput);
		return FALSE;
	}

	for (const auto& file : files)
	{
		std::ifstream inputFile(file.GetString(), std::ios::binary);
		if (!inputFile.is_open())
		{
			_ftprintf(stderr, _T("Failed to open input file: %s\n"), file.GetString());
			outputFile.close();
			return FALSE;
		}

		outputFile << inputFile.rdbuf();
		if (splitter)
			outputFile << splitter;

		inputFile.close();
	}

	outputFile.close();
	return TRUE;
}

std::string escapeYaraString(const std::string& input) {
	std::unordered_map<char, std::string> escapeMap = {
		{'"', "\\\""},
		{'\\', "\\\\"}
	};

	std::string result;
	for (char ch : input) {
		auto it = escapeMap.find(ch);
		if (it != escapeMap.end()) {
			result += it->second;
		}
		else {
			result += ch;
		}
	}
	return result;
}

BOOL GenYaraFromFile(LPCTSTR lpszInputFile, LPCTSTR lpszOutputFile)
{
	std::ifstream inputFile(lpszInputFile);
	if (!inputFile.is_open())
	{
		_ftprintf(stderr, _T("Failed to open input file: %s, err=%d\n"), lpszInputFile, GetLastError());
		return FALSE;
	}

	std::vector<std::string> strings;
	std::string line;
	std::getline(inputFile, line); // Skip 1st line
	while (std::getline(inputFile, line))
	{
		if (line.empty())
			continue;
		
		strings.push_back(escapeYaraString(line));
	}

	inputFile.close();

	if (!strings.size()) {
		if (PathFileExists(lpszOutputFile)) {
			if (!DeleteFile(lpszOutputFile)) {
				_ftprintf(stderr, _T("Failed to delete the output file: %s\n"), lpszOutputFile);
				return FALSE;
			}
		}
		return TRUE;
	}

	std::ofstream outputFile(lpszOutputFile);
	if (!outputFile.is_open())
	{
		_ftprintf(stderr, _T("Failed to open output file: %s\n"), lpszOutputFile);
		return FALSE;
	}

	int n = 0;
	for (const auto& str : strings)
	{
		n += 1;
		outputFile << "rule suspicious_strings_" << n << "\n";
		outputFile << "{\n";
		outputFile << "strings:\n";

		outputFile << "    $ = \"" << str << "\" nocase\n";
		outputFile << "    $ = \"" << str << "\" nocase wide\n";

		outputFile << "condition:\n";
		outputFile << "    any of them\n";
		outputFile << "}\n";
	}

	outputFile.close();
	return TRUE;
}

int Compile(LPCTSTR lpszCurrDir, BOOL merge)
{
	int ret = -1;
	WCHAR szCurrDir[MAX_PATH];
	CString strRulesDir;
	CString strSuspStringsInput, strSuspStringsOutput;
	GetCurrentDirectoryW(MAX_PATH, szCurrDir);

	GetEnvironmentVariable(_T("YARARULES"), strRulesDir.GetBuffer(MAX_PATH), MAX_PATH);
	strRulesDir.ReleaseBuffer();
	if (strRulesDir.GetLength() == 0) {
		strRulesDir = lpszCurrDir;
		if (strRulesDir.Right(1) != L"\\")
			strRulesDir += L"\\";
		strRulesDir += L"rules";
	}

	strSuspStringsInput.Format(_T("%s\\..\\suspicious-strings.txt"), strRulesDir.GetString());
	strSuspStringsOutput.Format(_T("%s\\suspicious-strings.yar"), strRulesDir.GetString());

	if (!GenYaraFromFile(strSuspStringsInput, strSuspStringsOutput)) {
		_ftprintf(stderr, _T("failed to GenYaraFromFile\n"));
		return 3;
	}

	SetCurrentDirectoryW(strRulesDir);

	std::vector<CString> rules;
	CString strApp;
	CString strArgs;
	CString strCmdline;
	STARTUPINFO startInfo;
	PROCESS_INFORMATION pi = { NULL, NULL };
	DWORD subpret;

	traverse_yar(L"", rules);
	if (rules.size() == 0) {
		_ftprintf(stderr, _T("found no rules\n"));
		ret = 1;
		goto _RET;
	}

	_ftprintf(stdout, _T("Number of rules: %d\n"), (int)rules.size());

	if (merge) {
		if (!merge_files(rules, "\r\n", L"allyar.tmp")) {
			_ftprintf(stderr, _T("failed to merge yara files\n"));
			ret = 2;
			goto _RET;
		}
		strArgs += L" allyar.tmp";
	}
	else {
		for (const auto& file : rules) {
			strArgs += L" ";
			if (file.Find(L" ") >= 0) {
				strArgs += L"\"";
				strArgs += file;
				strArgs += L"\"";
			}
			else {
				strArgs += file;
			}
		}
	}

	strArgs += L" all.yarc";

	GetEnvironmentVariable(_T("YARACAPP"), strApp.GetBuffer(MAX_PATH), MAX_PATH);
	strApp.ReleaseBuffer();
	if (!strApp.GetLength()) {
		strApp = lpszCurrDir;
		if (strApp.Right(1) != L"\\")
			strApp += L"\\";
		strApp += L"yara\\yarac32.exe";
	}

	strCmdline.Format(_T("\"%s\" %s"), (LPCWSTR)strApp, (LPCWSTR)strArgs);

	ZeroMemory(&startInfo, sizeof(STARTUPINFO));
	startInfo.cb = sizeof(STARTUPINFO);

	_ftprintf(stdout, _T("Compiling...\n"));

	if (!CreateProcessW(NULL, (LPWSTR)(LPCWSTR)strCmdline, NULL, NULL, FALSE, 0, NULL, NULL, &startInfo, &pi))
	{
		_ftprintf(stderr, _T("failed to run yarac32, err=%d\n"), GetLastError());
		ret = 2;
		goto _RET;
	}
	switch (WaitForSingleObject(pi.hProcess, INFINITE))
	{
	case WAIT_OBJECT_0:
		if (!GetExitCodeProcess(pi.hProcess, &subpret))
			goto _RET;
		if (subpret == 0) {
			_ftprintf(stdout, _T("Completed.\n"));
		}
		break;
	case WAIT_TIMEOUT:
		goto _RET;
	default:
		goto _RET;
	}

	ret = (int)subpret;
_RET:
	if (pi.hProcess) CloseHandle(pi.hProcess);
	if (pi.hThread) CloseHandle(pi.hThread);
	SetCurrentDirectoryW(szCurrDir);
	return ret;
}

void PrintUsage(LPCTSTR appname)
{
	_ftprintf(stderr, _T("yarchk 2.0\n"));
	_ftprintf(stderr, _T("Usage: \n    %s -t <threads> -y <yara_rule_dir>\n"), appname);
	_ftprintf(stderr, _T("    -h  show help\n"));
}

int Main2(int argc, TCHAR** argv) {

	SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);
	EnableDebugPrivilege();
	bIsElevated = IsElevated();

	std::list<PROCESSENTRY32> process_ls;
	int nFound = 0;
	int i = 0;
	int threads = 0;
	LPCTSTR lpszYaraFile = NULL;
	SYSTEM_INFO sysinfo;
	YaraAppMgr yamgr;
	std::list<CString> errls;
	TCHAR szProcPath[MAX_PATH];
	std::list<CString> rules;
	bool bCompiled = false;
	std::string tmp;
	CString tmp2;
	clock_t start_time, end_time;
	WORD originalColor;
	TCHAR szCurrDir[MAX_PATH] = _T("");
	int compile_yar = 0;
	GetModuleFileName(NULL, szCurrDir, MAX_PATH);
	*PathFindFileName(szCurrDir) = '\0';

	GetSystemInfo(&sysinfo);

	for (i = 1; i < argc; i++) {
		if (_tcsicmp(argv[i], _T("-t")) == 0 && i + 1 < argc) {
			threads = _ttoi(argv[i + 1]);
			i += 1;
		}
		else if (_tcsicmp(argv[i], _T("-y")) == 0 && i + 1 < argc) {
			lpszYaraFile = argv[i + 1];
			i += 1;
		}
		else if (_tcsicmp(argv[i], _T("-e")) == 0 && i + 1 < argc) {
			gYaraApp = argv[i + 1];
			i += 1;
		}
		else if (_tcsicmp(argv[i], _T("-c")) == 0) {
			compile_yar = 1;
		}
		else if (_tcsicmp(argv[i], _T("-c2")) == 0) {
			compile_yar = 2;
		}
		else if (_tcsicmp(argv[i], _T("-h")) == 0) {
			PrintUsage(argv[0]);
			return 1;
		}
		else {
			_ftprintf(stderr, _T("invalid args: %s\n"), argv[i]);
			PrintUsage(argv[0]);
			return 1;
		}
	}

	start_time = clock();

	if (compile_yar) {
		return Compile(szCurrDir, compile_yar==2);
	}

	fs::path rpath;
	if (!lpszYaraFile) {
		rpath = fs::path(szCurrDir) / _T("rules");
	}
	else {
		rpath = lpszYaraFile;
	}

	try {
		if (PathIsDirectory(rpath.c_str())) {
			if (PathFileExists((rpath / _T("all.yarc")).c_str())) {
				rules.push_back((rpath / _T("all.yarc")).c_str());
				bCompiled = true;
				originalColor = getConsoleCurrentColor();
				setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
				_ftprintf(stderr, _T("Using the pre-compiled all.yarc rules file for scanning!\n"));
				setConsoleColor(originalColor);
			}
			else {
				for (const auto& entry : fs::recursive_directory_iterator(rpath))
				{
					std::wstring ext = entry.path().extension();
					if (!entry.is_directory()
						&& entry.is_regular_file()
						&& (ext == L".yar" || ext == L".yara"))
					{
						rules.push_back(entry.path().c_str());
					}
				}
			}
		}
		else {
			rules.push_back(rpath.c_str());
			if (rpath.extension() == ".yarc" || rpath.extension() == ".yarac") {
				bCompiled = true;
			}
		}
	}
	catch (...)
	{

	}

	if (gYaraApp.GetLength() == 0) {
		if (!LocateYaraExe(gYaraApp.GetBuffer(MAX_PATH), MAX_PATH)) {
			_ftprintf(stderr, _T("error: yara APP not exists\n"));
			return -1;
		}
		gYaraApp.ReleaseBuffer();
	}
	if (!rules.size())
	{
		_ftprintf(stderr, _T("error: no yara rules given\n"));
		return -1;
	}
	if (threads <= 0) {
		threads = (int)(sysinfo.dwNumberOfProcessors * 0.8);
		if (threads == 0) {
			threads = 1;
		}
		else if (threads > 64) {
			threads = 64;
		}
	}

	if (!bIsElevated) {
		setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
		_ftprintf(stderr, _T("NOT ELEVATED! Please run as administrator by right-clicking and selecting 'Run as administrator'.\n"));
		setConsoleColor(originalColor);
		Sleep(2000);
	}

	_ftprintf(stderr, _T("Getting process list information...\n"));
	GetProcessList(process_ls);

	_ftprintf(stderr, _T("Start Checking...\n"));
	i = 0;
	for (std::list<PROCESSENTRY32>::iterator it = process_ls.begin(); gnCTRLC == 0 && it != process_ls.end(); it++, i++)
	{
		PROCESSENTRY32& proc = *it;
		HANDLE hProc;

		if (proc.th32ProcessID == 0 || proc.th32ProcessID == 4 || proc.th32ProcessID == GetCurrentProcessId())
			continue;


		hProc = OpenProcess(PROCESS_VM_READ, FALSE, proc.th32ProcessID);
		if (!hProc) {
			if (GetLastError() == ERROR_ACCESS_DENIED && !bIsElevated) {
				_ftprintf(stderr, _T("## %s(%d): Open process failed，try running as administrator\n"), proc.szExeFile, proc.th32ProcessID);
			}
			else if (GetLastError() == ERROR_INVALID_PARAMETER) {
				//exited?
				continue;
			}
			else {
				_ftprintf(stderr, _T("## %s(%d): Open process failed，error %d\n"), proc.szExeFile, proc.th32ProcessID, GetLastError());
			}
			continue;
		}
		CloseHandle(hProc);
		szProcPath[0] = 0;
		GetProcessPathByPid(proc.th32ProcessID, szProcPath, MAX_PATH);

		while (yamgr.get_proc_count() >= (DWORD)threads && gnCTRLC == 0) {
			Sleep(100);
			std::list<YaraApp*> justdone;
			yamgr.check_dead(&justdone);
			for (auto& app : justdone) {
				if (app->stdout_str.size()) {
					std::stringstream ss(app->stdout_str);
					while (std::getline(ss, tmp)) {
						tmp2 = tmp.c_str();
						tmp2.TrimRight();
						originalColor = getConsoleCurrentColor();
						setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
						_ftprintf(stdout, _T("#! %s, %s\n"), (LPCTSTR)tmp2, (LPCTSTR)app->m_target_proc_name);
						setConsoleColor(originalColor);
					}
				}
			}
		}
		if (gnCTRLC) {
			break;
		}
		tmp2.Format(_T("%d%% %d/%d, %s(%d)"), i * 100 / (int)process_ls.size(), i, (int)process_ls.size(), proc.szExeFile, proc.th32ProcessID);
		SetConsoleTitle(tmp2);
		if (!yamgr.run_yara(rules, bCompiled, proc.th32ProcessID, proc.szExeFile, szProcPath)) {
			_ftprintf(stderr, _T("## %s(%d): run yara failed\n"), proc.szExeFile, proc.th32ProcessID);
			continue;
		}
	}

	if (gnCTRLC) {
		yamgr.killall();
		SetConsoleTitle(_T("Exiting..."));
	}
	else {
		SetConsoleTitle(_T("Waiting && Ending..."));
	}
	while (yamgr.get_proc_count() > 0) {
		Sleep(100);
		yamgr.check_dead();
	}

	for (auto& app : yamgr.m_tasks_done) {
		if (app->stderr_str.size()) {
			std::stringstream ss(app->stderr_str);
			while (std::getline(ss, tmp)) {
				tmp2 = tmp.c_str();
				tmp2.TrimRight();
				_ftprintf(stderr, _T("## %s, Process Name: %s\n"),
					(LPCTSTR)tmp2, (LPCTSTR)app->m_target_proc_name);
			}
		}
	}

	int detected = 0;
	for (auto& app : yamgr.m_tasks_done) {
		if (app->stdout_str.size()) {
			std::stringstream ss(app->stdout_str);
			while (std::getline(ss, tmp)) {
				tmp2 = tmp.c_str();
				tmp2.TrimRight();
				detected++;
				if (detected == 1) {
					originalColor = getConsoleCurrentColor();
					setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
					_ftprintf(stdout, _T("DETECTED!\n"));
					setConsoleColor(originalColor);
				}
				if (app->m_target_proc_fullpath.GetLength()) {
					_ftprintf(stdout, _T(">> %s, Process Path: %s\n"),
						(LPCTSTR)tmp2, (LPCTSTR)app->m_target_proc_fullpath);
				}
				else {
					_ftprintf(stdout, _T(">> %s, Process Name: %s\n"),
						(LPCTSTR)tmp2, (LPCTSTR)app->m_target_proc_name);
				}

			}
		}
	}
	if (!detected) {
		_ftprintf(stdout, _T("No detected!\n"));
	}
	end_time = clock();
	int seconds = (end_time - start_time) / CLOCKS_PER_SEC;
	int hours = seconds / 3600;
	int minutes = (seconds % 3600) / 60;
	int seconds_remaining = seconds % 60;
	printf("Check completed, took %02d:%02d:%02d\n", hours, minutes, seconds_remaining);

	return 0;
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	int nRetCode = 0;
	setlocale(LC_ALL, "chs");
	
	CString strOrigTitle;
	GetConsoleTitle(strOrigTitle.GetBuffer(512), 512);
	strOrigTitle.ReleaseBuffer();
	nRetCode = Main2(argc, argv);
	SetConsoleTitle(strOrigTitle);

	return nRetCode;
}
