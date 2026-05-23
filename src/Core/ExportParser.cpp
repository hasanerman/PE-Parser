#include "Core/ExportParser.h"
#include "Utils/RVAUtils.h"

ExportInfo ExportParser::Parse(const BYTE* base, uint64_t fileSize,
    const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections)
{
    ExportInfo info = {};
    info.hasExports = false;

    const DataDirectoryEntry& exportDir = optHeader.dataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.isPresent) return info;

    DWORD offset = RVAToOffset(exportDir.virtualAddress, sections);
    if (offset == 0 || offset + sizeof(IMAGE_EXPORT_DIRECTORY) > fileSize) return info;

    auto* ied = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + offset);

    DWORD nameOff = RVAToOffset(ied->Name, sections);
    if (nameOff != 0 && nameOff < fileSize) {
        info.dllName = reinterpret_cast<const char*>(base + nameOff);
    }

    info.base              = ied->Base;
    info.numberOfFunctions = ied->NumberOfFunctions;
    info.numberOfNames     = ied->NumberOfNames;
    info.timeDateStamp     = ied->TimeDateStamp;
    info.hasExports        = true;

    DWORD funcTableOff    = RVAToOffset(ied->AddressOfFunctions,    sections);
    DWORD nameTableOff    = RVAToOffset(ied->AddressOfNames,        sections);
    DWORD ordinalTableOff = RVAToOffset(ied->AddressOfNameOrdinals, sections);

    auto* funcTable    = (funcTableOff    != 0) ? reinterpret_cast<const DWORD*> (base + funcTableOff)    : nullptr;
    auto* nameTable    = (nameTableOff    != 0) ? reinterpret_cast<const DWORD*> (base + nameTableOff)    : nullptr;
    auto* ordinalTable = (ordinalTableOff != 0) ? reinterpret_cast<const WORD*>  (base + ordinalTableOff) : nullptr;

    DWORD exportDirStart = exportDir.virtualAddress;
    DWORD exportDirEnd   = exportDirStart + exportDir.size;

    for (DWORD i = 0; i < ied->NumberOfNames && nameTable && ordinalTable && funcTable; ++i) {
        DWORD funcNameOff = RVAToOffset(nameTable[i], sections);
        if (funcNameOff == 0 || funcNameOff >= fileSize) continue;

        WORD  ord    = ordinalTable[i];
        if (ord >= ied->NumberOfFunctions) continue;
        DWORD rva    = funcTable[ord];

        ExportedFunction fn = {};
        fn.name     = reinterpret_cast<const char*>(base + funcNameOff);
        fn.rva      = rva;
        fn.ordinal  = static_cast<WORD>(ied->Base + ord);
        fn.hasName  = true;

        fn.isForwarder = (rva >= exportDirStart && rva < exportDirEnd);
        if (fn.isForwarder) {
            DWORD fwdOff = RVAToOffset(rva, sections);
            if (fwdOff != 0 && fwdOff < fileSize) {
                fn.forwarderName = reinterpret_cast<const char*>(base + fwdOff);
            }
        }

        info.functions.push_back(std::move(fn));
    }

    for (DWORD i = 0; i < ied->NumberOfFunctions && funcTable; ++i) {
        if (funcTable[i] == 0) continue;
        bool found = false;
        for (auto& fn : info.functions) {
            if (fn.rva == funcTable[i]) { found = true; break; }
        }
        if (!found) {
            ExportedFunction fn = {};
            fn.rva     = funcTable[i];
            fn.ordinal = static_cast<WORD>(ied->Base + i);
            fn.hasName = false;
            fn.name    = "#" + std::to_string(fn.ordinal);
            info.functions.push_back(std::move(fn));
        }
    }

    return info;
}
