#pragma once
#include "Core/PEData.h"

class FileHeaderParser {
public:
    static FileHeaderInfo Parse(const BYTE* base, uint64_t fileSize, DWORD peOffset);
};
