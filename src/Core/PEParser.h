#pragma once
#include "Core/PEData.h"

class PEParser {
public:
    static PEAnalysisResult Parse(const std::string& filePath);
    static PEAnalysisResult Parse(const std::wstring& filePath);
};
