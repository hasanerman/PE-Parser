#include "Core/FileHeaderParser.h"
#include "Utils/Characteristics.h"
#include "Utils/TimestampParser.h"

FileHeaderInfo FileHeaderParser::Parse(const BYTE* base, uint64_t fileSize, DWORD peOffset) {
    FileHeaderInfo info = {};

    if (!base || peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > fileSize) return info;

    DWORD sig = *reinterpret_cast<const DWORD*>(base + peOffset);
    if (sig != IMAGE_NT_SIGNATURE) return info;

    auto* fh = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + peOffset + sizeof(DWORD));

    info.machine               = fh->Machine;
    info.machineStr            = MachineToString(fh->Machine);
    info.numberOfSections      = fh->NumberOfSections;
    info.timeDateStamp         = fh->TimeDateStamp;
    info.timestampStr          = ParseTimestamp(fh->TimeDateStamp, info.isValidTimestamp);
    info.sizeOfOptionalHeader  = fh->SizeOfOptionalHeader;
    info.characteristics       = fh->Characteristics;
    info.isDLL                 = (fh->Characteristics & IMAGE_FILE_DLL)              != 0;
    info.isExe                 = (fh->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0;
    info.isDebug               = (fh->Characteristics & IMAGE_FILE_DEBUG_STRIPPED)   == 0;
    info.isLargeAddressAware   = (fh->Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
    info.is32BitMachine        = (fh->Characteristics & IMAGE_FILE_32BIT_MACHINE)    != 0;

    return info;
}
