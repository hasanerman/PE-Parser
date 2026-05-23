#pragma once
#include "Core/PEData.h"
#include <string>

class JSONExporter {
public:
    static bool Export(const PEAnalysisResult& result, const std::string& outputPath);
    static bool Export(const PEAnalysisResult& result, const std::wstring& outputPath);
};
