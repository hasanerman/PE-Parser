#pragma once
#include "Core/PEData.h"

class OptionalHeaderParser {
public:
    static OptionalHeaderInfo Parse(const BYTE* base, uint64_t fileSize, DWORD peOffset);
};
