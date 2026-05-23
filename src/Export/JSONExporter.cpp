#include "Export/JSONExporter.h"
#include "Utils/StringUtils.h"
#include "Utils/HexFormatter.h"
#include <fstream>
#include <sstream>
#include <iomanip>

static std::string Indent(int level) {
    return std::string(level * 2, ' ');
}

static std::string S(const std::string& s) {
    return "\"" + EscapeJSON(s) + "\"";
}

static std::string BuildJSON(const PEAnalysisResult& r) {
    std::ostringstream j;
    j << "{\n";

    j << Indent(1) << "\"file\": {\n";
    j << Indent(2) << "\"path\": " << S(r.filePath) << ",\n";
    j << Indent(2) << "\"name\": " << S(r.fileName) << ",\n";
    j << Indent(2) << "\"size\": " << r.fileSize << ",\n";
    j << Indent(2) << "\"architecture\": " << S(r.is64Bit ? "PE32+ (64-bit)" : "PE32 (32-bit)") << "\n";
    j << Indent(1) << "},\n";

    j << Indent(1) << "\"dos_header\": {\n";
    j << Indent(2) << "\"magic\": " << S(ToHex16(r.dosHeader.magic)) << ",\n";
    j << Indent(2) << "\"pe_offset\": " << S(ToHex32(r.dosHeader.peOffset)) << ",\n";
    j << Indent(2) << "\"valid\": " << BoolToStr(r.dosHeader.isValid) << "\n";
    j << Indent(1) << "},\n";

    j << Indent(1) << "\"file_header\": {\n";
    j << Indent(2) << "\"machine\": " << S(r.fileHeader.machineStr) << ",\n";
    j << Indent(2) << "\"machine_value\": " << S(ToHex16(r.fileHeader.machine)) << ",\n";
    j << Indent(2) << "\"number_of_sections\": " << r.fileHeader.numberOfSections << ",\n";
    j << Indent(2) << "\"timestamp\": " << S(r.fileHeader.timestampStr) << ",\n";
    j << Indent(2) << "\"timestamp_value\": " << r.fileHeader.timeDateStamp << ",\n";
    j << Indent(2) << "\"is_dll\": " << BoolToStr(r.fileHeader.isDLL) << ",\n";
    j << Indent(2) << "\"is_exe\": " << BoolToStr(r.fileHeader.isExe) << "\n";
    j << Indent(1) << "},\n";

    j << Indent(1) << "\"optional_header\": {\n";
    j << Indent(2) << "\"magic\": " << S(ToHex16(r.optionalHeader.magic)) << ",\n";
    j << Indent(2) << "\"image_base\": " << S(ToHex64(r.optionalHeader.imageBase)) << ",\n";
    j << Indent(2) << "\"entry_point\": " << S(ToHex32(r.optionalHeader.addressOfEntryPoint)) << ",\n";
    j << Indent(2) << "\"subsystem\": " << S(r.optionalHeader.subsystemStr) << ",\n";
    j << Indent(2) << "\"size_of_image\": " << r.optionalHeader.sizeOfImage << ",\n";
    j << Indent(2) << "\"aslr\": " << BoolToStr(r.optionalHeader.hasASLR) << ",\n";
    j << Indent(2) << "\"dep\": " << BoolToStr(r.optionalHeader.hasDEP) << ",\n";
    j << Indent(2) << "\"cfg\": " << BoolToStr(r.optionalHeader.hasCFGuard) << "\n";
    j << Indent(1) << "},\n";

    j << Indent(1) << "\"sections\": [\n";
    for (size_t i = 0; i < r.sections.size(); ++i) {
        const auto& s = r.sections[i];
        j << Indent(2) << "{\n";
        j << Indent(3) << "\"name\": "              << S(s.name) << ",\n";
        j << Indent(3) << "\"virtual_address\": "   << S(ToHex32(s.virtualAddress)) << ",\n";
        j << Indent(3) << "\"virtual_size\": "      << s.virtualSize << ",\n";
        j << Indent(3) << "\"raw_size\": "          << s.sizeOfRawData << ",\n";
        j << Indent(3) << "\"raw_offset\": "        << S(ToHex32(s.pointerToRawData)) << ",\n";
        j << Indent(3) << "\"entropy\": "           << std::fixed << std::setprecision(4) << s.entropy << ",\n";
        j << Indent(3) << "\"readable\": "          << BoolToStr(s.isReadable) << ",\n";
        j << Indent(3) << "\"writable\": "          << BoolToStr(s.isWritable) << ",\n";
        j << Indent(3) << "\"executable\": "        << BoolToStr(s.isExecutable) << ",\n";
        j << Indent(3) << "\"wx_suspicious\": "     << BoolToStr(s.isWX) << "\n";
        j << Indent(2) << "}" << (i + 1 < r.sections.size() ? "," : "") << "\n";
    }
    j << Indent(1) << "],\n";

    j << Indent(1) << "\"imports\": [\n";
    for (size_t i = 0; i < r.imports.size(); ++i) {
        const auto& lib = r.imports[i];
        j << Indent(2) << "{\n";
        j << Indent(3) << "\"library\": " << S(lib.name) << ",\n";
        j << Indent(3) << "\"function_count\": " << lib.functions.size() << ",\n";
        j << Indent(3) << "\"has_suspicious\": " << BoolToStr(lib.hasSuspiciousFunctions) << ",\n";
        j << Indent(3) << "\"functions\": [\n";
        for (size_t k = 0; k < lib.functions.size(); ++k) {
            const auto& fn = lib.functions[k];
            j << Indent(4) << "{ \"name\": " << S(fn.name)
              << ", \"by_ordinal\": " << BoolToStr(fn.importedByOrdinal)
              << ", \"suspicious\": " << BoolToStr(fn.isSuspicious) << " }"
              << (k + 1 < lib.functions.size() ? "," : "") << "\n";
        }
        j << Indent(3) << "]\n";
        j << Indent(2) << "}" << (i + 1 < r.imports.size() ? "," : "") << "\n";
    }
    j << Indent(1) << "],\n";

    j << Indent(1) << "\"exports\": {\n";
    j << Indent(2) << "\"has_exports\": " << BoolToStr(r.exports.hasExports) << ",\n";
    j << Indent(2) << "\"dll_name\": " << S(r.exports.dllName) << ",\n";
    j << Indent(2) << "\"number_of_functions\": " << r.exports.numberOfFunctions << ",\n";
    j << Indent(2) << "\"functions\": [\n";
    for (size_t i = 0; i < r.exports.functions.size(); ++i) {
        const auto& fn = r.exports.functions[i];
        j << Indent(3) << "{ \"name\": " << S(fn.name)
          << ", \"ordinal\": " << fn.ordinal
          << ", \"rva\": " << S(ToHex32(fn.rva))
          << ", \"forwarder\": " << BoolToStr(fn.isForwarder);
        if (fn.isForwarder) j << ", \"forwarder_name\": " << S(fn.forwarderName);
        j << " }" << (i + 1 < r.exports.functions.size() ? "," : "") << "\n";
    }
    j << Indent(2) << "]\n";
    j << Indent(1) << "},\n";

    j << Indent(1) << "\"tls\": {\n";
    j << Indent(2) << "\"has_tls\": " << BoolToStr(r.tls.hasTLS) << ",\n";
    j << Indent(2) << "\"callback_count\": " << r.tls.callbacks.size() << ",\n";
    j << Indent(2) << "\"callbacks\": [\n";
    for (size_t i = 0; i < r.tls.callbacks.size(); ++i) {
        j << Indent(3) << S(r.tls.callbacks[i].addressStr)
          << (i + 1 < r.tls.callbacks.size() ? "," : "") << "\n";
    }
    j << Indent(2) << "]\n";
    j << Indent(1) << "},\n";

    j << Indent(1) << "\"resources\": {\n";
    j << Indent(2) << "\"has_resources\": " << BoolToStr(r.resources.hasResources) << ",\n";
    j << Indent(2) << "\"count\": " << r.resources.entries.size() << ",\n";
    j << Indent(2) << "\"entries\": [\n";
    for (size_t i = 0; i < r.resources.entries.size(); ++i) {
        const auto& e = r.resources.entries[i];
        j << Indent(3) << "{ \"type\": " << S(e.typeName)
          << ", \"name\": " << S(e.name)
          << ", \"language\": " << S(e.languageStr)
          << ", \"size\": " << e.dataSize << " }"
          << (i + 1 < r.resources.entries.size() ? "," : "") << "\n";
    }
    j << Indent(2) << "]\n";
    j << Indent(1) << "},\n";

    j << Indent(1) << "\"analysis\": {\n";
    j << Indent(2) << "\"flag_count\": " << r.suspiciousFlags.size() << ",\n";
    j << Indent(2) << "\"flags\": [\n";
    for (size_t i = 0; i < r.suspiciousFlags.size(); ++i) {
        const auto& f = r.suspiciousFlags[i];
        std::string lvl = (f.level == SuspiciousLevel::Critical) ? "CRITICAL" :
                          (f.level == SuspiciousLevel::Warning)  ? "WARNING"  : "INFO";
        j << Indent(3) << "{ \"level\": " << S(lvl)
          << ", \"category\": " << S(f.category)
          << ", \"description\": " << S(f.description) << " }"
          << (i + 1 < r.suspiciousFlags.size() ? "," : "") << "\n";
    }
    j << Indent(2) << "]\n";
    j << Indent(1) << "}\n";

    j << "}\n";
    return j.str();
}

bool JSONExporter::Export(const PEAnalysisResult& result, const std::wstring& outputPath) {
    std::ofstream file(outputPath, std::ios::out | std::ios::trunc);
    if (!file.is_open()) return false;
    file << BuildJSON(result);
    return file.good();
}

bool JSONExporter::Export(const PEAnalysisResult& result, const std::string& outputPath) {
    return Export(result, AnsiToWide(outputPath));
}
