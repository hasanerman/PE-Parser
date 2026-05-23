#include "Core/VersionParser.h"
#include "Utils/StringUtils.h"
#include <vector>

#pragma comment(lib, "Version.lib")

VersionInfo VersionParser::Parse(const std::wstring& filePath) {
    VersionInfo info = {};
    info.hasVersionInfo = false;

    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (size == 0) {
        return info;
    }

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, data.data())) {
        return info;
    }

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate = nullptr;
    UINT cbTranslate = 0;

    if (!VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<LPVOID*>(&lpTranslate), &cbTranslate)) {
        return info;
    }

    if (cbTranslate < sizeof(LANGANDCODEPAGE) || lpTranslate == nullptr) {
        return info;
    }

    info.hasVersionInfo = true;

    auto QueryValue = [&](const wchar_t* name) -> std::string {
        wchar_t subBlock[256];
        swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage, name);
        
        wchar_t* value = nullptr;
        UINT valueSize = 0;
        if (VerQueryValueW(data.data(), subBlock, reinterpret_cast<LPVOID*>(&value), &valueSize) && value != nullptr) {
            return WideToAnsi(value);
        }
        return "";
    };

    info.companyName      = QueryValue(L"CompanyName");
    info.fileDescription  = QueryValue(L"FileDescription");
    info.fileVersion      = QueryValue(L"FileVersion");
    info.legalCopyright   = QueryValue(L"LegalCopyright");
    info.productName      = QueryValue(L"ProductName");
    info.productVersion   = QueryValue(L"ProductVersion");
    info.originalFilename = QueryValue(L"OriginalFilename");

    return info;
}
