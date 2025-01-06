#pragma once

#include "Thread.h"

BOOL
APIENTRY
MyCreatePipeEx(
	OUT LPHANDLE lpReadPipe,
	OUT LPHANDLE lpWritePipe,
	IN LPSECURITY_ATTRIBUTES lpPipeAttributes,
	IN DWORD nSize,
	DWORD dwReadMode,
	DWORD dwWriteMode
);

class SubProcess
	: public CThread
{
protected:
	HANDLE _hChildStd_IN_Rd;
	HANDLE _hChildStd_IN_Wr;
	HANDLE _hChildStd_OUT_Rd;
	HANDLE _hChildStd_OUT_Wr;
	HANDLE _hChildStd_ERR_Rd;
	HANDLE _hChildStd_ERR_Wr;

	PROCESS_INFORMATION mPI;
	CMyCriticalSection mCS;
public:
	enum {
		StderrIgnore = 0,
		StderrIntoStdout = 1,
		StderrAlone = 2
	};
	SubProcess();
	~SubProcess();

	bool CreateChild(const wchar_t* cmd, int tHandleStderr);
	void Close();
	int Write(const void *data, unsigned int len);
	bool WriteAll(const void *data, unsigned int len);
	int Read(void *buf, unsigned int *size, unsigned long timeout);
	int ReadStderr(void* buf, unsigned int* size, unsigned long timeout);

	bool EnablePushMode();
	bool WaitForProcessExitCode(DWORD timeout, DWORD* pEC);
	int  WaitForProcessExitCode2(DWORD timeout, DWORD* pEC);
	DWORD GetPid();

protected:
	bool InitPipes(bool bPipeForStderr);
	int ReadPipe(HANDLE &hPipe, void* buf, unsigned int* size, unsigned long timeout);

	virtual DWORD run();
	virtual void OnReadOutput(void *data, unsigned int len) {}
};
