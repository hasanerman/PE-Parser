#pragma once
#include <unordered_set>
#include <string>

namespace KnownMaliciousAPIs {

    inline const std::unordered_set<std::string>& GetCritical() {
        static const std::unordered_set<std::string> apis = {
            "VirtualAllocEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "NtQueueApcThread",
            "SetThreadContext",
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "MapViewOfFile",
            "MapViewOfFileEx",
        };
        return apis;
    }

    inline const std::unordered_set<std::string>& GetSuspicious() {
        static const std::unordered_set<std::string> apis = {
            "OpenProcess",
            "VirtualProtect",
            "VirtualProtectEx",
            "VirtualAlloc",
            "GetProcAddress",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "SetWindowsHookEx",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "FindWindow",
            "FindWindowA",
            "FindWindowW",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "OutputDebugString",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "NtSetInformationThread",
            "ZwSetInformationThread",
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32Next",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW",
            "URLDownloadToFile",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "InternetOpenUrl",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "WSAStartup",
            "connect",
            "socket",
            "bind",
            "listen",
            "accept",
            "send",
            "recv",
            "RegSetValueEx",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKey",
            "RegCreateKeyA",
            "RegCreateKeyW",
            "RegCreateKeyEx",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "CreateService",
            "CreateServiceA",
            "CreateServiceW",
            "StartService",
            "StartServiceA",
            "StartServiceW",
            "CryptEncrypt",
            "CryptDecrypt",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "RtlDecompressBuffer",
            "SuspendThread",
            "ResumeThread",
            "TerminateProcess",
            "CreateMutex",
            "CreateMutexA",
            "CreateMutexW",
            "GetAsyncKeyState",
            "SetFileAttributes",
            "DeleteFile",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFile",
            "CopyFile",
        };
        return apis;
    }

    inline bool IsCritical(const std::string& apiName) {
        return GetCritical().count(apiName) > 0;
    }

    inline bool IsSuspicious(const std::string& apiName) {
        return GetSuspicious().count(apiName) > 0;
    }

    inline bool IsAnyFlag(const std::string& apiName) {
        return IsCritical(apiName) || IsSuspicious(apiName);
    }
}
