#pragma once
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>

inline std::string ParseTimestamp(DWORD timestamp, bool& isValid) {
    if (timestamp == 0) {
        isValid = false;
        return "Not set (0x00000000)";
    }
    time_t t = static_cast<time_t>(timestamp);
    struct tm tmInfo = {};
    if (gmtime_s(&tmInfo, &t) != 0) {
        isValid = false;
        return "Invalid timestamp";
    }
    int year = tmInfo.tm_year + 1900;
    isValid = (year >= 1990 && year <= 2040);
    std::ostringstream ss;
    ss << std::put_time(&tmInfo, "%Y-%m-%d %H:%M:%S UTC");
    if (!isValid) ss << "  [Suspicious!]";
    return ss.str();
}
