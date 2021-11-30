// dllmain.cpp : Defines the entry point for the DLL application.

#include <stdlib.h>
#include <stdio.h>
#include <Shlwapi.h>    
#include <malloc.h>
#include <wchar.h>
#include <Windows.h>
#include <conio.h>
#include "detours.h"
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Shlwapi.lib")
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

HANDLE (WINAPI* UnhookedCreateFileW)(
               LPCWSTR               lpFileName,
               DWORD                 dwDesiredAccess,
               DWORD                 dwShareMode,
               LPSECURITY_ATTRIBUTES lpSecurityAttributes,
               DWORD                 dwCreationDisposition,
               DWORD                 dwFlagsAndAttributes,
               HANDLE                hTemplateFile
    ) = CreateFileW;

bool VerifyPathIntegrity(HANDLE hfile, WCHAR* path2) {

    DWORD last_error = GetLastError();

    if (hfile == INVALID_HANDLE_VALUE || !path2)
        return false;
    WCHAR* FinalPath = (WCHAR*)_malloca(4096 * sizeof(WCHAR));
    WCHAR* FullFinalPath = (WCHAR*)_malloca(4096 * sizeof(WCHAR));
    if (!GetFinalPathNameByHandleW(hfile, FinalPath, 4096, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS))//this is 0x0|0x0, writing NULL is enough but I like decorating my code
    {
        SetLastError(last_error);
        return false;
    }

    //strip off \\\\?\\ by skiping the first 3 characters
    for (int i = 0; i < 4092; i++) {
        FullFinalPath[i] = FinalPath[i + 4];
        FullFinalPath[i + 1] = L'\0';
    }
    bool ret = wcscmp(FullFinalPath, path2) == 0;
    _freea(FinalPath);
    _freea(FullFinalPath);
    SetLastError(last_error);
    return ret;
}
HANDLE WINAPI HookedCreateFileW(
                   LPCWSTR               lpFileName,
                   DWORD                 dwDesiredAccess,
                   DWORD                 dwShareMode,
                   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                   DWORD                 dwCreationDisposition,
                   DWORD                 dwFlagsAndAttributes,
                   HANDLE                hTemplateFile
) {

    bool IsTrusted = false;
    WCHAR* extension;
    WCHAR final_path[4096];
    HANDLE return_value = INVALID_HANDLE_VALUE;
    WCHAR prefix[4];
    WCHAR prefix2[32];
   
    //check if the path begin with c:\

    if (lstrlenW(lpFileName) > 3) {
        wmemcpy(prefix, lpFileName, 3);
        prefix[3] = L'\0';
        if (wcscmp(prefix, L"C:\\") != 0)
            goto ContinueUnhooked;
    }

    if (lstrlenW(lpFileName) >= 32) {
        wmemcpy(prefix2, lpFileName, 32);
        prefix2[31] = L'\0';
        if (wcscmp(prefix2, L"C:\\Windows\\Installer\\Config.Msi") == 0)
            goto ContinueUnhooked;
    }

    // we are specifically looking to hook CreateFileW in MsiCreateFileWithUserAccessCheck, so if a CreateFileW arguments doesn't match those, we will simply ignore them
    if (dwDesiredAccess != 0x410C0000 || dwShareMode != NULL || dwCreationDisposition != CREATE_ALWAYS)
        goto ContinueUnhooked;
    extension = PathFindExtensionW(lpFileName);
    if (wcscmp(extension, L".rbf") != 0)
        goto ContinueUnhooked;
    dwDesiredAccess |= DELETE;
    return_value = UnhookedCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, OPEN_ALWAYS, dwFlagsAndAttributes, hTemplateFile);
    if (return_value == INVALID_HANDLE_VALUE)
        return return_value;
    //handle exisiting file
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        DWORD lasterr = 0;
        IsTrusted = VerifyPathIntegrity(return_value, (WCHAR*)lpFileName);
        if (!IsTrusted) {
            SetLastError(ERROR_ACCESS_DENIED);
            CloseHandle(return_value);
            return INVALID_HANDLE_VALUE;  
        }
        //overwrite the file
        FILE_END_OF_FILE_INFO end_of_file_info = { 0 };
        end_of_file_info.EndOfFile.QuadPart = 0;
        SetFileInformationByHandle(return_value, FileEndOfFileInfo, &end_of_file_info, sizeof(end_of_file_info));
        SetLastError(lasterr);
        return return_value;
    }
    //handle a newly created file
    IsTrusted = VerifyPathIntegrity(return_value, (WCHAR*)lpFileName);
    if (!IsTrusted) {
        _FILE_DISPOSITION_INFO fdi = { TRUE };
        SetFileInformationByHandle(return_value, FileDispositionInfo, &fdi, sizeof(fdi));
        SetLastError(ERROR_ACCESS_DENIED);
        CloseHandle(return_value);
        return INVALID_HANDLE_VALUE;
    }
    return return_value;
ContinueUnhooked:
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

BOOL APIENTRY DllMain( HMODULE hModule,
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

