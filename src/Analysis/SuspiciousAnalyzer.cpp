#include "Analysis/SuspiciousAnalyzer.h"
#include "Analysis/KnownMaliciousAPIs.h"
#include "Utils/HexFormatter.h"
#include "Utils/RVAUtils.h"

static void AddFlag(std::vector<SuspiciousFlag>& flags, SuspiciousLevel level,
    const std::string& category, const std::string& desc)
{
    flags.push_back({ level, category, desc });
}

std::vector<SuspiciousFlag> SuspiciousAnalyzer::Analyze(const PEAnalysisResult& result,
    const BYTE* base, uint64_t fileSize)
{
    std::vector<SuspiciousFlag> flags;

    if (!result.isValid) return flags;

    for (const auto& sec : result.sections) {
        if (sec.isWX) {
            AddFlag(flags, SuspiciousLevel::Critical, "Section",
                "Section '" + sec.name + "' is both Writable and Executable (W+X) — process injection indicator");
        }
        if (sec.entropy > 7.2) {
            AddFlag(flags, SuspiciousLevel::Warning, "Entropy",
                "Section '" + sec.name + "' has very high entropy (" +
                FormatEntropy(sec.entropy) + ") — likely packed or encrypted");
        } else if (sec.entropy > 6.5 && sec.isExecutable) {
            AddFlag(flags, SuspiciousLevel::Info, "Entropy",
                "Executable section '" + sec.name + "' has elevated entropy (" +
                FormatEntropy(sec.entropy) + ")");
        }
    }

    DWORD epRVA = result.optionalHeader.addressOfEntryPoint;
    if (epRVA != 0 && !result.sections.empty()) {
        bool epInCode = false;
        for (const auto& sec : result.sections) {
            if (epRVA >= sec.virtualAddress && epRVA < sec.virtualAddress + max(sec.virtualSize, sec.sizeOfRawData)) {
                if (sec.isExecutable) { epInCode = true; break; }
            }
        }
        if (!epInCode) {
            AddFlag(flags, SuspiciousLevel::Critical, "Entry Point",
                "Entry point (" + ToHex32(epRVA) + ") is NOT inside an executable section — packer/injector indicator");
        }
    }

    if (!result.fileHeader.isValidTimestamp && result.fileHeader.timeDateStamp != 0) {
        AddFlag(flags, SuspiciousLevel::Warning, "Timestamp",
            "PE timestamp (" + result.fileHeader.timestampStr + ") is outside normal range — may be fake");
    }

    if (!result.optionalHeader.hasASLR) {
        AddFlag(flags, SuspiciousLevel::Warning, "Mitigations",
            "ASLR (DYNAMIC_BASE) is disabled — binary is not position-independent");
    }
    if (!result.optionalHeader.hasDEP) {
        AddFlag(flags, SuspiciousLevel::Warning, "Mitigations",
            "DEP/NX (NX_COMPAT) is disabled — binary can execute code from data sections");
    }

    if (result.tls.hasTLS) {
        AddFlag(flags, SuspiciousLevel::Warning, "TLS",
            "TLS directory is present — can execute code before the entry point (anti-debug technique)");
        if (!result.tls.callbacks.empty()) {
            AddFlag(flags, SuspiciousLevel::Critical, "TLS",
                "TLS callbacks detected (" + std::to_string(result.tls.callbacks.size()) +
                " callback(s)) — common anti-debugging and code hiding technique");
        }
    }

    for (const auto& lib : result.imports) {
        for (const auto& fn : lib.functions) {
            if (!fn.isSuspicious) continue;
            if (KnownMaliciousAPIs::IsCritical(fn.name)) {
                AddFlag(flags, SuspiciousLevel::Critical, "Import",
                    fn.name + " from " + lib.name + " — high-risk process manipulation API");
            } else {
                AddFlag(flags, SuspiciousLevel::Warning, "Import",
                    fn.name + " from " + lib.name + " — potentially suspicious API");
            }
        }
    }

    if (!result.exports.hasExports && result.imports.empty()) {
        AddFlag(flags, SuspiciousLevel::Warning, "Structure",
            "No imports and no exports detected — file may be heavily obfuscated or manually crafted");
    }

    if (!result.sections.empty()) {
        const auto& lastSec = result.sections.back();
        DWORD expectedEnd = lastSec.pointerToRawData + lastSec.sizeOfRawData;
        if (fileSize > expectedEnd + 512) {
            AddFlag(flags, SuspiciousLevel::Warning, "Overlay",
                "File has " + std::to_string(fileSize - expectedEnd) +
                " bytes of overlay data after the last section — may contain hidden payloads");
        }
    }

    for (const auto& sec : result.sections) {
        if (sec.name.empty() || sec.name == " ") {
            AddFlag(flags, SuspiciousLevel::Info, "Section",
                "Section with empty or blank name detected — uncommon in clean PE files");
        }
    }

    if (result.fileHeader.numberOfSections > 20) {
        AddFlag(flags, SuspiciousLevel::Warning, "Structure",
            "Unusually high section count (" + std::to_string(result.fileHeader.numberOfSections) +
            ") — may indicate malformed or crafted PE file");
    }

    int urlCount = 0;
    int ipCount = 0;
    for (const auto& s : result.strings) {
        if (s.isNetwork) {
            if (s.networkType == "URL" || s.networkType == "Domain") {
                urlCount++;
            } else if (s.networkType == "IP Address") {
                ipCount++;
            }
        }
    }
    if (urlCount > 0 || ipCount > 0) {
        AddFlag(flags, SuspiciousLevel::Warning, "Network Indicators",
            "Found " + std::to_string(urlCount) + " URL/domain(s) and " + std::to_string(ipCount) + " IP address(es) in binary strings");
    }

    if (flags.empty()) {
        AddFlag(flags, SuspiciousLevel::Info, "Overall",
            "No significant suspicious indicators found in this binary");
    }

    return flags;
}
