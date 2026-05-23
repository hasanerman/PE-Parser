#pragma once
#include "Core/PEData.h"
#include <vector>

class ImportParser {
public:
    static std::vector<ImportLibrary> Parse(const BYTE* base, uint64_t fileSize,
        const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections);
};
