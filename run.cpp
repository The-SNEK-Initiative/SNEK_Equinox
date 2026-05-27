#define _CRT_SECURE_NO_WINDOWS_PROTOTYPES
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")

int main(int argc, char** argv) {
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	
	if (!CreateProcessA(".\\bin\\spoof.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("spoof fail\n");
		return 1;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	if (!CreateProcessA(".\\bin\\vers.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("vers fail\n");
		return 1;
	}
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	if (!CreateProcessA(".\\bin\\Equinox.exe", NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		printf("Equinox fail\n");
		return 1;
	}
	
	printf("Running\n");
	WaitForSingleObject(pi.hProcess, INFINITE);
	
	return 0;
}
