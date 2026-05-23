#include "Core/DebugParser.h"
#include "Utils/RVAUtils.h"
#include "Utils/HexFormatter.h"
#include <iomanip>
#include <sstream>

DebugInfo DebugParser::Parse(const BYTE* base, uint64_t size, const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections) {
    DebugInfo info = {};
    info.hasDebugInfo = false;

    const auto& debugDirEntry = optHeader.dataDirectories[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (!debugDirEntry.isPresent || debugDirEntry.virtualAddress == 0 || debugDirEntry.size == 0) {
        return info;
    }

    DWORD offset = RVAToOffset(debugDirEntry.virtualAddress, sections);
    if (!IsSafeOffset(base, size, offset, debugDirEntry.size)) {
        return info;
    }

    DWORD entryCount = debugDirEntry.size / sizeof(IMAGE_DEBUG_DIRECTORY);
    const auto* debugDirs = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(base + offset);

    for (DWORD i = 0; i < entryCount; ++i) {
        const auto& dir = debugDirs[i];
        if (dir.Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
            if (dir.PointerToRawData == 0 || dir.PointerToRawData + dir.SizeOfData > size) {
                continue;
            }

            const BYTE* data = base + dir.PointerToRawData;
            if (dir.SizeOfData < sizeof(DWORD)) {
                continue;
            }

            DWORD sig = *reinterpret_cast<const DWORD*>(data);
            if (sig == 0x53445352) {
                if (dir.SizeOfData < 24) continue;
                info.hasDebugInfo = true;
                info.format = "RSDS (PDB 7.0)";
                
                const auto* guid = reinterpret_cast<const GUID*>(data + 4);
                info.age = *reinterpret_cast<const DWORD*>(data + 20);
                
                std::stringstream ss;
                ss << std::hex << std::setfill('0')
                   << std::setw(8) << guid->Data1 << "-"
                   << std::setw(4) << guid->Data2 << "-"
                   << std::setw(4) << guid->Data3 << "-";
                for (int j = 0; j < 8; ++j) {
                    if (j == 2) ss << "-";
                    ss << std::setw(2) << static_cast<int>(guid->Data4[j]);
                }
                info.guid = ss.str();
                
                const char* pdbName = reinterpret_cast<const char*>(data + 24);
                DWORD maxNameLen = dir.SizeOfData - 24;
                std::string nameStr;
                for (DWORD k = 0; k < maxNameLen && pdbName[k] != '\0'; ++k) {
                    nameStr += pdbName[k];
                }
                info.pdbPath = nameStr;
                break;
            } else if (sig == 0x3031424E) {
                if (dir.SizeOfData < 16) continue;
                info.hasDebugInfo = true;
                info.format = "NB10 (PDB 2.0)";
                
                DWORD timestamp = *reinterpret_cast<const DWORD*>(data + 8);
                info.age = *reinterpret_cast<const DWORD*>(data + 12);
                
                std::stringstream ss;
                ss << std::hex << std::setfill('0') << std::setw(8) << timestamp;
                info.guid = ss.str();
                
                const char* pdbName = reinterpret_cast<const char*>(data + 16);
                DWORD maxNameLen = dir.SizeOfData - 16;
                std::string nameStr;
                for (DWORD k = 0; k < maxNameLen && pdbName[k] != '\0'; ++k) {
                    nameStr += pdbName[k];
                }
                info.pdbPath = nameStr;
                break;
            }
        }
    }

    return info;
}
