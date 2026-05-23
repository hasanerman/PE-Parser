#pragma once
#include <windows.h>
#include <vector>
#include "Core/PEData.h"

class DebugParser {
public:
    static DebugInfo Parse(const BYTE* base, uint64_t size, const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections);
};
