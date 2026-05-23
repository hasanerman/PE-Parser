#pragma once
#include "Core/PEData.h"
#include <vector>

class ResourceParser {
public:
    static ResourceInfo Parse(const BYTE* base, uint64_t fileSize,
        const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections);
};
