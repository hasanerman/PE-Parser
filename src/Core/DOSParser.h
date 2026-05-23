#pragma once
#include "Core/PEData.h"
#include "Core/PEFile.h"

class DOSParser {
public:
    static DOSHeaderInfo Parse(const PEFile& file);
};
