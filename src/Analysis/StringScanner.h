#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "Core/PEData.h"

class StringScanner {
public:
    static std::vector<PEStringInfo> Scan(const BYTE* base, uint64_t size, const std::vector<SectionInfo>& sections);
};
