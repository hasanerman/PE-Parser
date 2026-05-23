#include "Core/PEParser.h"
#include "Core/PEFile.h"
#include "Core/DOSParser.h"
#include "Core/FileHeaderParser.h"
#include "Core/OptionalHeaderParser.h"
#include "Core/SectionParser.h"
#include "Core/ImportParser.h"
#include "Core/ExportParser.h"
#include "Core/TLSParser.h"
#include "Core/ResourceParser.h"
#include "Core/DebugParser.h"
#include "Core/VersionParser.h"
#include "Analysis/StringScanner.h"
#include "Analysis/SuspiciousAnalyzer.h"
#include "Utils/StringUtils.h"
#include <imagehlp.h>

#pragma comment(lib, "imagehlp.lib")

PEAnalysisResult PEParser::Parse(const std::wstring& filePath) {
    PEAnalysisResult result = {};
    result.isValid  = false;
    result.filePath = WideToAnsi(filePath);
    result.fileName = GetFileNameFromPath(filePath);

    PEFile file;
    if (!file.Load(filePath)) {
        result.errorMessage = "Failed to open or map file: " + result.filePath;
        return result;
    }

    result.fileSize = file.GetSize();
    const BYTE* base = file.GetBase();
    uint64_t    size = file.GetSize();

    result.dosHeader = DOSParser::Parse(file);
    if (!result.dosHeader.isValid) {
        result.errorMessage = "Invalid PE file: MZ signature not found";
        return result;
    }

    DWORD peOffset = result.dosHeader.peOffset;
    if (peOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > size) {
        result.errorMessage = "PE header offset out of bounds";
        return result;
    }

    DWORD sig = *reinterpret_cast<const DWORD*>(base + peOffset);
    if (sig != IMAGE_NT_SIGNATURE) {
        result.errorMessage = "Invalid PE signature at e_lfanew offset";
        return result;
    }

    result.fileHeader    = FileHeaderParser::Parse(base, size, peOffset);
    result.optionalHeader = OptionalHeaderParser::Parse(base, size, peOffset);
    result.is64Bit       = result.optionalHeader.is64Bit;

    result.sections      = SectionParser::Parse(base, size, peOffset, result.fileHeader.numberOfSections);
    result.imports       = ImportParser::Parse(base, size, result.optionalHeader, result.sections);
    result.exports       = ExportParser::Parse(base, size, result.optionalHeader, result.sections);
    result.tls           = TLSParser::Parse(base, size, result.optionalHeader, result.sections);
    result.resources     = ResourceParser::Parse(base, size, result.optionalHeader, result.sections);
    result.debug         = DebugParser::Parse(base, size, result.optionalHeader, result.sections);
    result.version       = VersionParser::Parse(filePath);
    result.strings       = StringScanner::Scan(base, size, result.sections);

    DWORD headerSum = 0;
    DWORD calcSum = 0;
    if (MapFileAndCheckSumW(filePath.c_str(), &headerSum, &calcSum) == CHECKSUM_SUCCESS) {
        result.computedChecksum = calcSum;
        result.isChecksumValid = (headerSum == calcSum);
    } else {
        result.computedChecksum = 0;
        result.isChecksumValid = false;
    }

    uint64_t lastSectionEnd = 0;
    for (const auto& sec : result.sections) {
        uint64_t endOffset = static_cast<uint64_t>(sec.pointerToRawData) + sec.sizeOfRawData;
        if (endOffset > lastSectionEnd) {
            lastSectionEnd = endOffset;
        }
    }
    if (lastSectionEnd < result.fileSize && lastSectionEnd > 0) {
        result.hasOverlay = true;
        result.overlayOffset = lastSectionEnd;
        result.overlaySize = result.fileSize - lastSectionEnd;
    } else {
        result.hasOverlay = false;
        result.overlayOffset = 0;
        result.overlaySize = 0;
    }

    result.suspiciousFlags = SuspiciousAnalyzer::Analyze(result, base, size);

    result.isValid = true;
    return result;
}

PEAnalysisResult PEParser::Parse(const std::string& filePath) {
    return Parse(AnsiToWide(filePath));
}
