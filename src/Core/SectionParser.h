#pragma once
#include "Core/PEData.h"
#include <vector>

class SectionParser {
public:
    static std::vector<SectionInfo> Parse(const BYTE* base, uint64_t fileSize,
        DWORD peOffset, WORD numberOfSections);
};
