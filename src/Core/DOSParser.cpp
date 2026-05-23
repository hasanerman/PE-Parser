#include "Core/DOSParser.h"

DOSHeaderInfo DOSParser::Parse(const PEFile& file) {
    DOSHeaderInfo info = {};
    const BYTE* base   = file.GetBase();
    uint64_t    size   = file.GetSize();

    if (size < sizeof(IMAGE_DOS_HEADER)) {
        info.isValid = false;
        return info;
    }

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);

    info.magic           = dos->e_magic;
    info.lastPageBytes   = dos->e_cblp;
    info.pageCount       = dos->e_cp;
    info.relocCount      = dos->e_crlc;
    info.headerSize      = dos->e_cparhdr;
    info.minAlloc        = dos->e_minalloc;
    info.maxAlloc        = dos->e_maxalloc;
    info.initialSS       = dos->e_ss;
    info.initialSP       = dos->e_sp;
    info.checksum        = dos->e_csum;
    info.initialIP       = dos->e_ip;
    info.initialCS       = dos->e_cs;
    info.relocTableOffset = dos->e_lfarlc;
    info.overlayNumber   = dos->e_ovno;
    info.oemIdentifier   = dos->e_oemid;
    info.oemInfo         = dos->e_oeminfo;
    info.peOffset        = dos->e_lfanew;
    info.isValid         = (dos->e_magic == IMAGE_DOS_SIGNATURE);

    return info;
}
