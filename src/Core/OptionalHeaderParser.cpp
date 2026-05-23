#include "Core/OptionalHeaderParser.h"
#include "Utils/Characteristics.h"

static const char* s_dataDirNames[16] = {
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug",
    "Architecture",
    "Global Ptr",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "Import Address Table",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved"
};

static void FillDataDirectories(OptionalHeaderInfo& info, const IMAGE_DATA_DIRECTORY* dirs, DWORD count) {
    for (DWORD i = 0; i < 16 && i < count; ++i) {
        info.dataDirectories[i].virtualAddress = dirs[i].VirtualAddress;
        info.dataDirectories[i].size           = dirs[i].Size;
        info.dataDirectories[i].name           = s_dataDirNames[i];
        info.dataDirectories[i].isPresent      = (dirs[i].VirtualAddress != 0);
    }
}

OptionalHeaderInfo OptionalHeaderParser::Parse(const BYTE* base, uint64_t fileSize, DWORD peOffset) {
    OptionalHeaderInfo info = {};
    DWORD optOffset = peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (optOffset + sizeof(WORD) > fileSize) return info;

    WORD magic = *reinterpret_cast<const WORD*>(base + optOffset);
    info.magic    = magic;
    info.is64Bit  = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (optOffset + sizeof(IMAGE_OPTIONAL_HEADER32) > fileSize) return info;
        auto* oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(base + optOffset);

        info.majorLinkerVersion       = oh->MajorLinkerVersion;
        info.minorLinkerVersion       = oh->MinorLinkerVersion;
        info.sizeOfCode               = oh->SizeOfCode;
        info.sizeOfInitializedData    = oh->SizeOfInitializedData;
        info.sizeOfUninitializedData  = oh->SizeOfUninitializedData;
        info.addressOfEntryPoint      = oh->AddressOfEntryPoint;
        info.baseOfCode               = oh->BaseOfCode;
        info.imageBase                = oh->ImageBase;
        info.sectionAlignment         = oh->SectionAlignment;
        info.fileAlignment            = oh->FileAlignment;
        info.majorOSVersion           = oh->MajorOperatingSystemVersion;
        info.minorOSVersion           = oh->MinorOperatingSystemVersion;
        info.majorImageVersion        = oh->MajorImageVersion;
        info.minorImageVersion        = oh->MinorImageVersion;
        info.majorSubsystemVersion    = oh->MajorSubsystemVersion;
        info.minorSubsystemVersion    = oh->MinorSubsystemVersion;
        info.sizeOfImage              = oh->SizeOfImage;
        info.sizeOfHeaders            = oh->SizeOfHeaders;
        info.checkSum                 = oh->CheckSum;
        info.subsystem                = oh->Subsystem;
        info.subsystemStr             = SubsystemToString(oh->Subsystem);
        info.dllCharacteristics       = oh->DllCharacteristics;
        info.sizeOfStackReserve       = oh->SizeOfStackReserve;
        info.sizeOfStackCommit        = oh->SizeOfStackCommit;
        info.sizeOfHeapReserve        = oh->SizeOfHeapReserve;
        info.sizeOfHeapCommit         = oh->SizeOfHeapCommit;
        info.numberOfRvaAndSizes      = oh->NumberOfRvaAndSizes;
        FillDataDirectories(info, oh->DataDirectory, oh->NumberOfRvaAndSizes);

    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (optOffset + sizeof(IMAGE_OPTIONAL_HEADER64) > fileSize) return info;
        auto* oh = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(base + optOffset);

        info.majorLinkerVersion       = oh->MajorLinkerVersion;
        info.minorLinkerVersion       = oh->MinorLinkerVersion;
        info.sizeOfCode               = oh->SizeOfCode;
        info.sizeOfInitializedData    = oh->SizeOfInitializedData;
        info.sizeOfUninitializedData  = oh->SizeOfUninitializedData;
        info.addressOfEntryPoint      = oh->AddressOfEntryPoint;
        info.baseOfCode               = oh->BaseOfCode;
        info.imageBase                = oh->ImageBase;
        info.sectionAlignment         = oh->SectionAlignment;
        info.fileAlignment            = oh->FileAlignment;
        info.majorOSVersion           = oh->MajorOperatingSystemVersion;
        info.minorOSVersion           = oh->MinorOperatingSystemVersion;
        info.majorImageVersion        = oh->MajorImageVersion;
        info.minorImageVersion        = oh->MinorImageVersion;
        info.majorSubsystemVersion    = oh->MajorSubsystemVersion;
        info.minorSubsystemVersion    = oh->MinorSubsystemVersion;
        info.sizeOfImage              = oh->SizeOfImage;
        info.sizeOfHeaders            = oh->SizeOfHeaders;
        info.checkSum                 = oh->CheckSum;
        info.subsystem                = oh->Subsystem;
        info.subsystemStr             = SubsystemToString(oh->Subsystem);
        info.dllCharacteristics       = oh->DllCharacteristics;
        info.sizeOfStackReserve       = oh->SizeOfStackReserve;
        info.sizeOfStackCommit        = oh->SizeOfStackCommit;
        info.sizeOfHeapReserve        = oh->SizeOfHeapReserve;
        info.sizeOfHeapCommit         = oh->SizeOfHeapCommit;
        info.numberOfRvaAndSizes      = oh->NumberOfRvaAndSizes;
        FillDataDirectories(info, oh->DataDirectory, oh->NumberOfRvaAndSizes);
    }

    info.hasASLR         = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)    != 0;
    info.hasDEP          = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)       != 0;
    info.hasCFGuard      = (info.dllCharacteristics & 0x4000)                                   != 0;
    info.hasHighEntropyVA = (info.dllCharacteristics & 0x0020)                                  != 0;
    info.hasForceIntegrity= (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0;

    return info;
}
