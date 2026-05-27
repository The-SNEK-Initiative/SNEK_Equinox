#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#pragma comment(lib,"advapi32.lib")

DWORD SetVer(const wchar_t* v) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	DWORD len = (wcslen(v) + 1) * sizeof(wchar_t);
	RegSetValueExW(hk, L"EngineVersion", 0, REG_SZ, (LPBYTE)v, len);
	RegCloseKey(hk);
	return 0;
}

DWORD SetPltf(const wchar_t* v) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	DWORD len = (wcslen(v) + 1) * sizeof(wchar_t);
	RegSetValueExW(hk, L"PlatformVersion", 0, REG_SZ, (LPBYTE)v, len);
	RegCloseKey(hk);
	return 0;
}

DWORD SetLstU(DWORD t) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	RegSetValueExW(hk, L"LastUpdate", 0, REG_DWORD, (LPBYTE)&t, sizeof(t));
	RegCloseKey(hk);
	return 0;
}

DWORD SetASigV(const wchar_t* v) {
	HKEY hk = NULL;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
		return 1;
	DWORD len = (wcslen(v) + 1) * sizeof(wchar_t);
	RegSetValueExW(hk, L"AVSignatureVersion", 0, REG_SZ, (LPBYTE)v, len);
	RegCloseKey(hk);
	return 0;
}

DWORD SpfV() {
	DWORD nt = GetTickCount() / 1000;
	SetVer(L"1.1.19400.10");
	SetPltf(L"4.18.2306.1024");
	SetLstU(nt);
	SetASigV(L"1.393.456");
	return 0;
}

int main() {
	SpfV();
	return 0;
}
