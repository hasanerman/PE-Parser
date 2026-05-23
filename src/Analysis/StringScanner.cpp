#include "Analysis/StringScanner.h"
#include <cctype>

static void AnalyzeNetworkIndicator(const std::string& val, bool& isNetwork, std::string& netType) {
    isNetwork = false;
    netType = "";

    std::string lower = val;
    for (char& c : lower) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }

    if (lower.find("http://") != std::string::npos ||
        lower.find("https://") != std::string::npos ||
        lower.find("ftp://") != std::string::npos) {
        isNetwork = true;
        netType = "URL";
        return;
    }

    if (lower.find("www.") != std::string::npos) {
        isNetwork = true;
        netType = "Domain";
        return;
    }

    static const std::vector<std::string> tlds = {
        ".com", ".net", ".org", ".xyz", ".info", ".biz", ".ru", ".cn", ".cc", ".io"
    };

    for (const auto& tld : tlds) {
        size_t idx = lower.find(tld);
        if (idx != std::string::npos) {
            if (idx + tld.length() == lower.length() || lower[idx + tld.length()] == '/' || lower[idx + tld.length()] == ':') {
                if (idx > 0 && (isalnum(static_cast<unsigned char>(lower[idx - 1])) || lower[idx - 1] == '.' || lower[idx - 1] == '-')) {
                    isNetwork = true;
                    netType = "Domain";
                    return;
                }
            }
        }
    }

    for (size_t i = 0; i < lower.length(); ++i) {
        if (isdigit(static_cast<unsigned char>(lower[i]))) {
            int parts[4] = {0, 0, 0, 0};
            int partIdx = 0;
            size_t k = i;
            bool ok = true;
            while (partIdx < 4 && k < lower.length()) {
                if (isdigit(static_cast<unsigned char>(lower[k]))) {
                    parts[partIdx] = parts[partIdx] * 10 + (lower[k] - '0');
                    if (parts[partIdx] > 255) {
                        ok = false;
                        break;
                    }
                    k++;
                } else if (lower[k] == '.') {
                    if (k == i || lower[k - 1] == '.') {
                        ok = false;
                        break;
                    }
                    partIdx++;
                    k++;
                } else {
                    break;
                }
            }
            if (ok && partIdx == 3 && k > i && isdigit(static_cast<unsigned char>(lower[k - 1]))) {
                isNetwork = true;
                netType = "IP Address";
                return;
            }
        }
    }
}

static std::string GetSectionForOffset(uint64_t offset, const std::vector<SectionInfo>& sections, DWORD& rva) {
    rva = 0;
    for (const auto& sec : sections) {
        if (offset >= sec.pointerToRawData && offset < sec.pointerToRawData + sec.sizeOfRawData) {
            rva = sec.virtualAddress + static_cast<DWORD>(offset - sec.pointerToRawData);
            return sec.name;
        }
    }
    if (offset < 4096) {
        rva = static_cast<DWORD>(offset);
        return "HEADERS";
    }
    return "OVERLAY";
}

std::vector<PEStringInfo> StringScanner::Scan(const BYTE* base, uint64_t size, const std::vector<SectionInfo>& sections) {
    std::vector<PEStringInfo> results;
    results.reserve(5000);

    std::string asciiBuf;
    uint64_t asciiStart = 0;

    for (uint64_t i = 0; i < size; ++i) {
        BYTE c = base[i];
        if (c >= 0x20 && c <= 0x7E) {
            if (asciiBuf.empty()) {
                asciiStart = i;
            }
            asciiBuf += static_cast<char>(c);
        } else {
            if (asciiBuf.length() >= 4) {
                PEStringInfo strInfo;
                strInfo.value = asciiBuf;
                strInfo.offset = asciiStart;
                strInfo.isUnicode = false;
                strInfo.section = GetSectionForOffset(asciiStart, sections, strInfo.rva);
                AnalyzeNetworkIndicator(strInfo.value, strInfo.isNetwork, strInfo.networkType);
                results.push_back(strInfo);
            }
            asciiBuf.clear();
        }
    }
    if (asciiBuf.length() >= 4) {
        PEStringInfo strInfo;
        strInfo.value = asciiBuf;
        strInfo.offset = asciiStart;
        strInfo.isUnicode = false;
        strInfo.section = GetSectionForOffset(asciiStart, sections, strInfo.rva);
        AnalyzeNetworkIndicator(strInfo.value, strInfo.isNetwork, strInfo.networkType);
        results.push_back(strInfo);
    }

    std::string uniBuf;
    uint64_t uniStart = 0;

    for (uint64_t i = 0; i + 1 < size; i += 2) {
        BYTE c1 = base[i];
        BYTE c2 = base[i + 1];
        if (c1 >= 0x20 && c1 <= 0x7E && c2 == 0x00) {
            if (uniBuf.empty()) {
                uniStart = i;
            }
            uniBuf += static_cast<char>(c1);
        } else {
            if (uniBuf.length() >= 4) {
                PEStringInfo strInfo;
                strInfo.value = uniBuf;
                strInfo.offset = uniStart;
                strInfo.isUnicode = true;
                strInfo.section = GetSectionForOffset(uniStart, sections, strInfo.rva);
                AnalyzeNetworkIndicator(strInfo.value, strInfo.isNetwork, strInfo.networkType);
                results.push_back(strInfo);
            }
            uniBuf.clear();
        }
    }
    if (uniBuf.length() >= 4) {
        PEStringInfo strInfo;
        strInfo.value = uniBuf;
        strInfo.offset = uniStart;
        strInfo.isUnicode = true;
        strInfo.section = GetSectionForOffset(uniStart, sections, strInfo.rva);
        AnalyzeNetworkIndicator(strInfo.value, strInfo.isNetwork, strInfo.networkType);
        results.push_back(strInfo);
    }

    for (uint64_t i = 1; i + 1 < size; i += 2) {
        BYTE c1 = base[i];
        BYTE c2 = base[i + 1];
        if (c1 >= 0x20 && c1 <= 0x7E && c2 == 0x00) {
            if (uniBuf.empty()) {
                uniStart = i;
            }
            uniBuf += static_cast<char>(c1);
        } else {
            if (uniBuf.length() >= 4) {
                PEStringInfo strInfo;
                strInfo.value = uniBuf;
                strInfo.offset = uniStart;
                strInfo.isUnicode = true;
                strInfo.section = GetSectionForOffset(uniStart, sections, strInfo.rva);
                AnalyzeNetworkIndicator(strInfo.value, strInfo.isNetwork, strInfo.networkType);
                results.push_back(strInfo);
            }
            uniBuf.clear();
        }
    }
    if (uniBuf.length() >= 4) {
        PEStringInfo strInfo;
        strInfo.value = uniBuf;
        strInfo.offset = uniStart;
        strInfo.isUnicode = true;
        strInfo.section = GetSectionForOffset(uniStart, sections, strInfo.rva);
        AnalyzeNetworkIndicator(strInfo.value, strInfo.isNetwork, strInfo.networkType);
        results.push_back(strInfo);
    }

    return results;
}
