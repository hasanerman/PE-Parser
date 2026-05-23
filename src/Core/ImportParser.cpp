#include "Core/ImportParser.h"
#include "Utils/RVAUtils.h"
#include "Analysis/KnownMaliciousAPIs.h"

static std::vector<ImportedFunction> ParseThunks32(const BYTE* base, uint64_t fileSize,
    DWORD intRVA, DWORD iatRVA, const std::vector<SectionInfo>& sections)
{
    std::vector<ImportedFunction> funcs;
    DWORD offset = RVAToOffset(intRVA != 0 ? intRVA : iatRVA, sections);
    if (offset == 0) return funcs;

    auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA32*>(base + offset);
    while (offset + sizeof(IMAGE_THUNK_DATA32) <= fileSize && thunk->u1.AddressOfData != 0) {
        ImportedFunction fn = {};
        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
            fn.importedByOrdinal = true;
            fn.ordinal           = IMAGE_ORDINAL32(thunk->u1.Ordinal);
            fn.name              = "#" + std::to_string(fn.ordinal);
        } else {
            DWORD nameOff = RVAToOffset(thunk->u1.AddressOfData, sections);
            if (nameOff != 0 && nameOff + sizeof(IMAGE_IMPORT_BY_NAME) <= fileSize) {
                auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + nameOff);
                fn.hint = ibn->Hint;
                fn.name = reinterpret_cast<const char*>(ibn->Name);
                fn.importedByOrdinal = false;
            }
        }
        fn.isSuspicious = KnownMaliciousAPIs::IsAnyFlag(fn.name);
        funcs.push_back(fn);
        ++thunk;
        offset += sizeof(IMAGE_THUNK_DATA32);
    }
    return funcs;
}

static std::vector<ImportedFunction> ParseThunks64(const BYTE* base, uint64_t fileSize,
    DWORD intRVA, DWORD iatRVA, const std::vector<SectionInfo>& sections)
{
    std::vector<ImportedFunction> funcs;
    DWORD offset = RVAToOffset(intRVA != 0 ? intRVA : iatRVA, sections);
    if (offset == 0) return funcs;

    auto* thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(base + offset);
    while (offset + sizeof(IMAGE_THUNK_DATA64) <= fileSize && thunk->u1.AddressOfData != 0) {
        ImportedFunction fn = {};
        if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
            fn.importedByOrdinal = true;
            fn.ordinal           = IMAGE_ORDINAL64(thunk->u1.Ordinal);
            fn.name              = "#" + std::to_string(fn.ordinal);
        } else {
            DWORD nameOff = RVAToOffset(static_cast<DWORD>(thunk->u1.AddressOfData), sections);
            if (nameOff != 0 && nameOff + sizeof(IMAGE_IMPORT_BY_NAME) <= fileSize) {
                auto* ibn = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + nameOff);
                fn.hint = ibn->Hint;
                fn.name = reinterpret_cast<const char*>(ibn->Name);
                fn.importedByOrdinal = false;
            }
        }
        fn.isSuspicious = KnownMaliciousAPIs::IsAnyFlag(fn.name);
        funcs.push_back(fn);
        ++thunk;
        offset += sizeof(IMAGE_THUNK_DATA64);
    }
    return funcs;
}

std::vector<ImportLibrary> ImportParser::Parse(const BYTE* base, uint64_t fileSize,
    const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections)
{
    std::vector<ImportLibrary> libs;
    const DataDirectoryEntry& importDir = optHeader.dataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.isPresent) return libs;

    DWORD offset = RVAToOffset(importDir.virtualAddress, sections);
    if (offset == 0) return libs;

    auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + offset);
    while (offset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= fileSize &&
           (desc->Name != 0 || desc->FirstThunk != 0)) {
        if (desc->Name == 0) { ++desc; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR); continue; }

        DWORD nameOff = RVAToOffset(desc->Name, sections);
        if (nameOff == 0) { ++desc; offset += sizeof(IMAGE_IMPORT_DESCRIPTOR); continue; }

        ImportLibrary lib = {};
        lib.name = reinterpret_cast<const char*>(base + nameOff);

        if (optHeader.is64Bit) {
            lib.functions = ParseThunks64(base, fileSize, desc->OriginalFirstThunk, desc->FirstThunk, sections);
        } else {
            lib.functions = ParseThunks32(base, fileSize, desc->OriginalFirstThunk, desc->FirstThunk, sections);
        }

        lib.hasSuspiciousFunctions = false;
        for (auto& fn : lib.functions) {
            if (fn.isSuspicious) { lib.hasSuspiciousFunctions = true; break; }
        }

        libs.push_back(std::move(lib));
        ++desc;
        offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return libs;
}
