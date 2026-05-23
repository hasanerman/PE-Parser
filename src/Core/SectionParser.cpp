#include "Core/SectionParser.h"
#include "Analysis/EntropyCalculator.h"

std::vector<SectionInfo> SectionParser::Parse(const BYTE* base, uint64_t fileSize,
    DWORD peOffset, WORD numberOfSections)
{
    std::vector<SectionInfo> sections;
    if (!base || numberOfSections == 0) return sections;

    DWORD fhOffset  = peOffset + sizeof(DWORD);
    auto* fh        = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + fhOffset);
    DWORD secOffset = fhOffset + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader;

    for (WORD i = 0; i < numberOfSections; ++i) {
        DWORD entryOffset = secOffset + static_cast<DWORD>(i) * sizeof(IMAGE_SECTION_HEADER);
        if (entryOffset + sizeof(IMAGE_SECTION_HEADER) > fileSize) break;

        auto* sh = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + entryOffset);

        SectionInfo sec = {};
        char nameBuf[9] = {};
        memcpy(nameBuf, sh->Name, 8);
        sec.name              = nameBuf;
        sec.virtualSize       = sh->Misc.VirtualSize;
        sec.virtualAddress    = sh->VirtualAddress;
        sec.sizeOfRawData     = sh->SizeOfRawData;
        sec.pointerToRawData  = sh->PointerToRawData;
        sec.characteristics   = sh->Characteristics;
        sec.isReadable        = (sh->Characteristics & IMAGE_SCN_MEM_READ)    != 0;
        sec.isWritable        = (sh->Characteristics & IMAGE_SCN_MEM_WRITE)   != 0;
        sec.isExecutable      = (sh->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sec.isWX              = sec.isWritable && sec.isExecutable;

        DWORD rawEnd = sh->PointerToRawData + sh->SizeOfRawData;
        if (sh->PointerToRawData != 0 && sh->SizeOfRawData != 0 && rawEnd <= fileSize) {
            sec.entropy = CalculateEntropy(base + sh->PointerToRawData, sh->SizeOfRawData);
        } else {
            sec.entropy = 0.0;
        }

        sections.push_back(sec);
    }
    return sections;
}
