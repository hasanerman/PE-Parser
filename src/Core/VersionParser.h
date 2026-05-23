#pragma once
#include <windows.h>
#include <string>
#include "Core/PEData.h"

class VersionParser {
public:
    static VersionInfo Parse(const std::wstring& filePath);
};
