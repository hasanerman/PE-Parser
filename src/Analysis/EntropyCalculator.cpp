#include "Analysis/EntropyCalculator.h"
#include <cmath>
#include <array>

double CalculateEntropy(const BYTE* data, size_t size) {
    if (!data || size == 0) return 0.0;
    std::array<uint64_t, 256> freq = {};
    for (size_t i = 0; i < size; ++i) {
        freq[data[i]]++;
    }
    double entropy = 0.0;
    double invSize  = 1.0 / static_cast<double>(size);
    for (int i = 0; i < 256; ++i) {
        if (freq[i] == 0) continue;
        double p = static_cast<double>(freq[i]) * invSize;
        entropy -= p * std::log2(p);
    }
    return entropy;
}
