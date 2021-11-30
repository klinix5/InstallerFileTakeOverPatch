// dllmain.cpp : Defines the entry point for the DLL application.

#include <stdlib.h>
#include <stdio.h>
#include <Shlwapi.h>    
#include <malloc.h>
#include <wchar.h>
#include <Windows.h>
#include <conio.h>
#include <Objbase.h>
#include "detours.h"
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Ole32.lib")
bool IsWindowsInstallerSvcLoadingLibrary() {

    //simple check, we will open windows installer service and check if it is running
    //if the service is running, we will check if the PID equal ours
    SC_HANDLE sc_mgr = OpenSCManager(NULL, NULL, STANDARD_RIGHTS_READ);
    if (sc_mgr == NULL)
        return false;
    SC_HANDLE svc = OpenServiceW(sc_mgr, L"msiserver", SERVICE_QUERY_STATUS);
    CloseServiceHandle(sc_mgr);
    if (svc == NULL)
        return false;
    DWORD out_info_sz = 0;
    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, NULL, NULL, &out_info_sz);
    SERVICE_STATUS_PROCESS* svc_status = (SERVICE_STATUS_PROCESS*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, out_info_sz);
    QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)svc_status, out_info_sz, &out_info_sz);
    CloseServiceHandle(svc);
    if (svc_status->dwProcessId != GetCurrentProcessId()) {
        HeapFree(GetProcessHeap(), NULL, svc_status);
        return false;
    }
    HeapFree(GetProcessHeap(), NULL, svc_status);
    return true;
}


HANDLE(WINAPI* UnhookedCreateFileW)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    ) = CreateFileW;

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
) {

    WCHAR* extension;
    WCHAR* prefix;
    WCHAR* prefix_temp;
    WCHAR* prefix1;
    WCHAR* prefix1_temp;
    WCHAR* prefix2;
    WCHAR* prefix2_temp;
    WCHAR* vvalue;
    DWORD prefix_sz = 0;
    DWORD prefix1_sz = 0;
    DWORD prefix2_sz = 0;
    DWORD vvalue_sz = 0;
    DWORD type = REG_SZ;
    HKEY cfg;
    prefix_sz = ExpandEnvironmentStrings(L"%SystemDrive%\\", NULL, NULL);
    prefix = (WCHAR*)_malloca(prefix_sz * sizeof(WCHAR));
    ExpandEnvironmentStrings(L"%SystemDrive%\\", prefix, prefix_sz);
    prefix1_sz = ExpandEnvironmentStringsW(L"%SystemDrive%\\Config.Msi", NULL, NULL);
    prefix1 = (WCHAR*)_malloca(prefix1_sz * sizeof(WCHAR));
    ExpandEnvironmentStrings(L"%SystemDrive%\\Config.Msi", prefix1, prefix1_sz);
    prefix2_sz = ExpandEnvironmentStringsW(L"%SystemRoot%\\Installer\\Config.Msi", NULL, NULL);
    prefix2 = (WCHAR*)_malloca(prefix2_sz * sizeof(WCHAR));
    ExpandEnvironmentStrings(L"%SystemRoot%\\Installer\\Config.Msi", prefix2, prefix2_sz);
    vvalue_sz = ExpandEnvironmentStringsW(L"%SystemDrive%\\Config.Msi\\", NULL, NULL);
    vvalue = (WCHAR*)_malloca(vvalue_sz * sizeof(WCHAR));
    ExpandEnvironmentStringsW(L"%SystemDrive%\\Config.Msi\\", vvalue, vvalue_sz);
    prefix_temp = (WCHAR*)_malloca(prefix_sz * sizeof(WCHAR));
    prefix1_temp = (WCHAR*)_malloca(prefix1_sz * sizeof(WCHAR));
    prefix2_temp = (WCHAR*)_malloca(prefix2_sz * sizeof(WCHAR));
    // we are specifically looking to hook CreateFileW in msi.dll!MsiCreateFileWithUserAccessCheck, so if a CreateFileW arguments doesn't match those, we will simply ignore it
    if (dwDesiredAccess != 0x410C0000 || dwShareMode != NULL || dwCreationDisposition != CREATE_ALWAYS)
        goto ContinueUnhooked;
    extension = PathFindExtensionW(lpFileName);
    if (lstrlenW(lpFileName) < 3)
        goto ContinueUnhooked;
    if (_wcsicmp(extension, L".rbf") != 0)
        goto ContinueUnhooked;
    if (lstrlenW(lpFileName) > prefix_sz) {
        wmemcpy(prefix_temp, lpFileName, prefix_sz - 1);
        prefix_temp[prefix_sz - 1] = L'\0';
        if (_wcsicmp(prefix, prefix_temp) != 0)
            goto ContinueUnhooked;
    }
    if (lstrlenW(lpFileName) > prefix2_sz) {
        wmemcpy(prefix2_temp, lpFileName, prefix2_sz - 1);
        prefix2_temp[prefix2_sz - 1];
        if (_wcsicmp(prefix2, prefix2_temp) == 0)
            goto ContinueUnhooked;
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Folders", NULL, KEY_QUERY_VALUE, &cfg) != ERROR_SUCCESS) {
        goto ContinueUnhooked;
    }
    if (RegQueryValueExW(cfg, vvalue, NULL, &type, NULL, NULL) == ERROR_SUCCESS) {
        RegCloseKey(cfg);
        if (lstrlenW(lpFileName) > prefix1_sz) {
            wmemcpy(prefix1_temp, lpFileName, prefix1_sz - 1);
            prefix1_temp[prefix1_sz - 1] = L'\0';
            if (_wcsicmp(prefix1, prefix1_temp) == 0)
                goto ContinueUnhooked;
        }
    }
    RegCloseKey(cfg);
    _freea(prefix);
    _freea(prefix_temp);
    _freea(prefix1);
    _freea(prefix1_temp);
    _freea(prefix2);
    _freea(prefix2_temp);
    SetLastError(ERROR_ACCESS_DENIED);
    return INVALID_HANDLE_VALUE;
ContinueUnhooked:
    _freea(prefix);
    _freea(prefix_temp);
    _freea(prefix1);
    _freea(prefix1_temp);
    _freea(prefix2);
    _freea(prefix2_temp);
    return UnhookedCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL LoadHook() {

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)UnhookedCreateFileW, HookedCreateFileW);
    ULONG err = DetourTransactionCommit();
    if (err != NO_ERROR)
        return FALSE;
    return TRUE;
}

BOOL UnloadHook() {

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)UnhookedCreateFileW, HookedCreateFileW);
    ULONG err = DetourTransactionCommit();
    if (err != NO_ERROR)
        return FALSE;
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        /*if (!IsWindowsInstallerSvcLoadingLibrary())
            return FALSE;*/
        LoadHook();
        return TRUE;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        return UnloadHook();
        break;
    }
    return TRUE;
}

