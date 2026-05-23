#pragma once
#include <windows.h>
#include <string>
#include <vector>

inline std::string MachineToString(WORD machine) {
    switch (machine) {
    case 0x0000: return "Unknown";
    case 0x014C: return "x86 (Intel 386)";
    case 0x0162: return "MIPS R3000 LE";
    case 0x0168: return "MIPS R10000";
    case 0x0184: return "Alpha AXP";
    case 0x01C0: return "ARM LE";
    case 0x01C2: return "ARM Thumb";
    case 0x01C4: return "ARM Thumb-2 LE";
    case 0x01F0: return "PowerPC LE";
    case 0x0200: return "Intel Itanium (IA-64)";
    case 0x0266: return "MIPS16";
    case 0x0366: return "MIPS FPU";
    case 0x0466: return "MIPS FPU16";
    case 0x0EBC: return "EFI Bytecode";
    case 0x8664: return "x64 (AMD64)";
    case 0xAA64: return "ARM64 LE";
    default: {
        char buf[32];
        sprintf_s(buf, "Unknown (0x%04X)", machine);
        return buf;
    }
    }
}

inline std::string SubsystemToString(WORD subsystem) {
    switch (subsystem) {
    case 0:  return "Unknown";
    case 1:  return "Native";
    case 2:  return "Windows GUI";
    case 3:  return "Windows Console (CUI)";
    case 5:  return "OS/2 Character";
    case 7:  return "POSIX Character";
    case 9:  return "Windows CE";
    case 10: return "EFI Application";
    case 11: return "EFI Boot Service Driver";
    case 12: return "EFI Runtime Driver";
    case 13: return "EFI ROM";
    case 14: return "Xbox";
    case 16: return "Windows Boot Application";
    default: return "Unknown";
    }
}

inline std::vector<std::string> FileCharacteristicsToStrings(WORD chars) {
    std::vector<std::string> result;
    if (chars & IMAGE_FILE_RELOCS_STRIPPED)        result.push_back("RELOCS_STRIPPED");
    if (chars & IMAGE_FILE_EXECUTABLE_IMAGE)       result.push_back("EXECUTABLE_IMAGE");
    if (chars & IMAGE_FILE_LINE_NUMS_STRIPPED)     result.push_back("LINE_NUMS_STRIPPED");
    if (chars & IMAGE_FILE_LOCAL_SYMS_STRIPPED)    result.push_back("LOCAL_SYMS_STRIPPED");
    if (chars & 0x0010)                            result.push_back("AGGRESSIVE_WS_TRIM");
    if (chars & IMAGE_FILE_LARGE_ADDRESS_AWARE)    result.push_back("LARGE_ADDRESS_AWARE");
    if (chars & IMAGE_FILE_32BIT_MACHINE)          result.push_back("32BIT_MACHINE");
    if (chars & IMAGE_FILE_DEBUG_STRIPPED)         result.push_back("DEBUG_STRIPPED");
    if (chars & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) result.push_back("REMOVABLE_RUN_FROM_SWAP");
    if (chars & IMAGE_FILE_NET_RUN_FROM_SWAP)      result.push_back("NET_RUN_FROM_SWAP");
    if (chars & IMAGE_FILE_SYSTEM)                 result.push_back("SYSTEM");
    if (chars & IMAGE_FILE_DLL)                    result.push_back("DLL");
    if (chars & IMAGE_FILE_UP_SYSTEM_ONLY)         result.push_back("UP_SYSTEM_ONLY");
    return result;
}

inline std::string SectionPermissionsToString(bool r, bool w, bool x) {
    std::string perm;
    perm += r ? "R" : "-";
    perm += w ? "W" : "-";
    perm += x ? "X" : "-";
    return perm;
}

inline std::string ResourceTypeToString(DWORD typeId) {
    switch (typeId) {
    case 1:  return "RT_CURSOR";
    case 2:  return "RT_BITMAP";
    case 3:  return "RT_ICON";
    case 4:  return "RT_MENU";
    case 5:  return "RT_DIALOG";
    case 6:  return "RT_STRING";
    case 7:  return "RT_FONTDIR";
    case 8:  return "RT_FONT";
    case 9:  return "RT_ACCELERATOR";
    case 10: return "RT_RCDATA";
    case 11: return "RT_MESSAGETABLE";
    case 12: return "RT_GROUP_CURSOR";
    case 14: return "RT_GROUP_ICON";
    case 16: return "RT_VERSION";
    case 17: return "RT_DLGINCLUDE";
    case 19: return "RT_PLUGPLAY";
    case 20: return "RT_VXD";
    case 21: return "RT_ANICURSOR";
    case 22: return "RT_ANIICON";
    case 23: return "RT_HTML";
    case 24: return "RT_MANIFEST";
    default: {
        char buf[32];
        sprintf_s(buf, "RT_UNKNOWN (%lu)", typeId);
        return buf;
    }
    }
}

inline std::string LanguageToString(WORD langId) {
    WORD primary = PRIMARYLANGID(langId);
    switch (primary) {
    case LANG_ENGLISH:    return "English";
    case LANG_TURKISH:    return "Turkish";
    case LANG_GERMAN:     return "German";
    case LANG_FRENCH:     return "French";
    case LANG_SPANISH:    return "Spanish";
    case LANG_ARABIC:     return "Arabic";
    case LANG_CHINESE:    return "Chinese";
    case LANG_JAPANESE:   return "Japanese";
    case LANG_KOREAN:     return "Korean";
    case LANG_RUSSIAN:    return "Russian";
    case LANG_PORTUGUESE: return "Portuguese";
    case LANG_ITALIAN:    return "Italian";
    case LANG_DUTCH:      return "Dutch";
    case LANG_POLISH:     return "Polish";
    case LANG_NEUTRAL:    return "Neutral";
    default: {
        char buf[32];
        sprintf_s(buf, "Unknown (0x%04X)", langId);
        return buf;
    }
    }
}

inline std::vector<std::string> DLLCharacteristicsToStrings(WORD chars) {
    std::vector<std::string> result;
    if (chars & 0x0020) result.push_back("HIGH_ENTROPY_VA");
    if (chars & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)   result.push_back("DYNAMIC_BASE (ASLR)");
    if (chars & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) result.push_back("FORCE_INTEGRITY");
    if (chars & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)      result.push_back("NX_COMPAT (DEP)");
    if (chars & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION)   result.push_back("NO_ISOLATION");
    if (chars & IMAGE_DLLCHARACTERISTICS_NO_SEH)         result.push_back("NO_SEH");
    if (chars & IMAGE_DLLCHARACTERISTICS_NO_BIND)        result.push_back("NO_BIND");
    if (chars & 0x1000)                                  result.push_back("APPCONTAINER");
    if (chars & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER)     result.push_back("WDM_DRIVER");
    if (chars & 0x4000)                                  result.push_back("GUARD_CF");
    if (chars & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) result.push_back("TERMINAL_SERVER_AWARE");
    return result;
}
