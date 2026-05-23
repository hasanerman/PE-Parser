#include "Core/ResourceParser.h"
#include "Utils/RVAUtils.h"
#include "Utils/Characteristics.h"

static const BYTE* s_rsrcBase = nullptr;
static DWORD       s_rsrcRVA  = 0;

static void WalkLevel2(const BYTE* base, uint64_t fileSize,
    DWORD dirOffset, const std::string& typeName, DWORD typeId,
    bool typeHasName, std::vector<ResourceEntry>& entries)
{
    if (dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) return;
    auto* dir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(base + dirOffset);
    DWORD total = dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    DWORD entryBase = dirOffset + sizeof(IMAGE_RESOURCE_DIRECTORY);

    for (DWORD i = 0; i < total; ++i) {
        DWORD entOff = entryBase + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        if (entOff + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileSize) break;
        auto* ent = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(base + entOff);

        std::string resName;
        DWORD       resId = 0;
        bool        hasName = false;

        if (ent->NameIsString) {
            hasName = true;
            DWORD strOff = (ent->NameOffset & 0x7FFFFFFF);
            if (strOff + sizeof(WORD) < fileSize) {
                WORD len = *reinterpret_cast<const WORD*>(base + strOff);
                const wchar_t* wstr = reinterpret_cast<const wchar_t*>(base + strOff + sizeof(WORD));
                for (WORD c = 0; c < len && (strOff + sizeof(WORD) + c * 2) < fileSize; ++c)
                    resName += static_cast<char>(wstr[c]);
            }
        } else {
            resId = ent->Id;
            resName = std::to_string(resId);
        }

        if (ent->DataIsDirectory) {
            DWORD subDir = ent->OffsetToDirectory & 0x7FFFFFFF;
            if (subDir + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;
            auto* langDir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(base + subDir);
            DWORD langTotal = langDir->NumberOfNamedEntries + langDir->NumberOfIdEntries;
            DWORD langBase  = subDir + sizeof(IMAGE_RESOURCE_DIRECTORY);

            for (DWORD l = 0; l < langTotal; ++l) {
                DWORD langEntOff = langBase + l * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
                if (langEntOff + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileSize) break;
                auto* langEnt = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(base + langEntOff);
                if (langEnt->DataIsDirectory) continue;

                DWORD dataEntOff = langEnt->OffsetToData;
                if (dataEntOff + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > fileSize) continue;
                auto* data = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(base + dataEntOff);

                ResourceEntry entry = {};
                entry.typeName    = typeName;
                entry.typeId      = typeId;
                entry.typeHasName = typeHasName;
                entry.name        = resName;
                entry.nameId      = resId;
                entry.nameHasName = hasName;
                entry.languageId  = static_cast<WORD>(langEnt->Id);
                entry.languageStr = LanguageToString(entry.languageId);
                entry.dataRVA     = data->OffsetToData;
                entry.dataSize    = data->Size;
                entry.codePage    = data->CodePage;
                entries.push_back(entry);
            }
        }
    }
}

ResourceInfo ResourceParser::Parse(const BYTE* base, uint64_t fileSize,
    const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections)
{
    ResourceInfo info = {};
    info.hasResources = false;

    const DataDirectoryEntry& rsrcDir = optHeader.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!rsrcDir.isPresent) return info;

    DWORD offset = RVAToOffset(rsrcDir.virtualAddress, sections);
    if (offset == 0 || offset + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) return info;

    info.hasResources = true;

    auto* rootDir = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(base + offset);
    DWORD total   = rootDir->NumberOfNamedEntries + rootDir->NumberOfIdEntries;
    DWORD entBase = offset + sizeof(IMAGE_RESOURCE_DIRECTORY);

    for (DWORD i = 0; i < total; ++i) {
        DWORD entOff = entBase + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);
        if (entOff + sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileSize) break;
        auto* ent = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(base + entOff);

        std::string typeName;
        DWORD       typeId   = 0;
        bool        typeHasName = false;

        if (ent->NameIsString) {
            typeHasName = true;
            DWORD strOff = ent->NameOffset & 0x7FFFFFFF;
            if (strOff + sizeof(WORD) < fileSize) {
                WORD len = *reinterpret_cast<const WORD*>(base + strOff);
                const wchar_t* wstr = reinterpret_cast<const wchar_t*>(base + strOff + sizeof(WORD));
                for (WORD c = 0; c < len; ++c) typeName += static_cast<char>(wstr[c]);
            }
        } else {
            typeId   = ent->Id;
            typeName = ResourceTypeToString(typeId);
        }

        if (ent->DataIsDirectory) {
            DWORD subOff = ent->OffsetToDirectory & 0x7FFFFFFF;
            WalkLevel2(base, fileSize, subOff, typeName, typeId, typeHasName, info.entries);
        }
    }

    return info;
}
