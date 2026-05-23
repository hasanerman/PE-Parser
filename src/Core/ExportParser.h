#pragma once
#include "Core/PEData.h"
#include <vector>

class ExportParser {
public:
    static ExportInfo Parse(const BYTE* base, uint64_t fileSize,
        const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections);
};
