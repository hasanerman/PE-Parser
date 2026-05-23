#pragma once
#include "Core/PEData.h"
#include <vector>

class TLSParser {
public:
    static TLSInfo Parse(const BYTE* base, uint64_t fileSize,
        const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections);
};
