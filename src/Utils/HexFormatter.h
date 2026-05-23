#pragma once
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

inline std::string ToHex8(BYTE v) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<DWORD>(v);
    return ss.str();
}

inline std::string ToHex16(WORD v) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setw(4) << std::setfill('0') << v;
    return ss.str();
}

inline std::string ToHex32(DWORD v) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setw(8) << std::setfill('0') << v;
    return ss.str();
}

inline std::string ToHex64(uint64_t v) {
    std::ostringstream ss;
    ss << "0x" << std::uppercase << std::hex << std::setw(16) << std::setfill('0') << v;
    return ss.str();
}

inline std::string FormatFileSize(uint64_t bytes) {
    constexpr uint64_t KB = 1024ULL;
    constexpr uint64_t MB = 1024ULL * 1024;
    constexpr uint64_t GB = 1024ULL * 1024 * 1024;
    if (bytes < KB) return std::to_string(bytes) + " B";
    if (bytes < MB) return std::to_string(bytes / KB) + " KB (" + std::to_string(bytes) + " bytes)";
    if (bytes < GB) return std::to_string(bytes / MB) + " MB (" + std::to_string(bytes) + " bytes)";
    return std::to_string(bytes / GB) + " GB (" + std::to_string(bytes) + " bytes)";
}

inline std::string FormatEntropy(double entropy) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(4) << entropy;
    return ss.str();
}
