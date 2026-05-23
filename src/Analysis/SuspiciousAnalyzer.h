#pragma once
#include "Core/PEData.h"
#include <vector>

class SuspiciousAnalyzer {
public:
    static std::vector<SuspiciousFlag> Analyze(const PEAnalysisResult& result,
        const BYTE* base, uint64_t fileSize);
};
