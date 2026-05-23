#pragma once
#include <windows.h>
#include <vector>
#include "Core/PEData.h"

inline DWORD RVAToOffset(DWORD rva, const std::vector<SectionInfo>& sections) {
    for (const auto& sec : sections) {
        DWORD secStart = sec.virtualAddress;
        DWORD rawEnd   = sec.pointerToRawData + sec.sizeOfRawData;
        DWORD virtEnd  = sec.virtualAddress + max(sec.virtualSize, sec.sizeOfRawData);
        if (rva >= secStart && rva < virtEnd) {
            DWORD offset = sec.pointerToRawData + (rva - secStart);
            if (offset < rawEnd) return offset;
        }
    }
    return 0;
}

inline const BYTE* RVAToPointer(DWORD rva, const BYTE* base, const std::vector<SectionInfo>& sections) {
    DWORD offset = RVAToOffset(rva, sections);
    if (offset == 0) return nullptr;
    return base + offset;
}

inline bool IsValidRVA(DWORD rva, const std::vector<SectionInfo>& sections) {
    return RVAToOffset(rva, sections) != 0;
}

inline bool IsSafeOffset(const BYTE* base, uint64_t fileSize, DWORD offset, DWORD size = 1) {
    if (offset == 0) return false;
    return static_cast<uint64_t>(offset) + size <= fileSize;
}
