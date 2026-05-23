#include "Utils/StringUtils.h"
#include <sstream>
#include <iomanip>

std::string WideToAnsi(const std::wstring& wide) {
    if (wide.empty()) return {};
    int len = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string result(len - 1, 0);
    WideCharToMultiByte(CP_ACP, 0, wide.c_str(), -1, result.data(), len, nullptr, nullptr);
    return result;
}

std::wstring AnsiToWide(const std::string& ansi) {
    if (ansi.empty()) return {};
    int len = MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, nullptr, 0);
    if (len <= 0) return {};
    std::wstring result(len - 1, 0);
    MultiByteToWideChar(CP_ACP, 0, ansi.c_str(), -1, result.data(), len);
    return result;
}

std::string Join(const std::vector<std::string>& parts, const std::string& sep) {
    std::string result;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) result += sep;
        result += parts[i];
    }
    return result;
}

std::string TrimString(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string GetFileNameFromPath(const std::string& path) {
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

std::string GetFileNameFromPath(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    std::wstring wname = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    return WideToAnsi(wname);
}

bool EndsWith(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string EscapeJSON(const std::string& str) {
    std::ostringstream ss;
    for (unsigned char c : str) {
        switch (c) {
        case '"':  ss << "\\\""; break;
        case '\\': ss << "\\\\"; break;
        case '\b': ss << "\\b";  break;
        case '\f': ss << "\\f";  break;
        case '\n': ss << "\\n";  break;
        case '\r': ss << "\\r";  break;
        case '\t': ss << "\\t";  break;
        default:
            if (c < 0x20) {
                ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
            } else {
                ss << c;
            }
            break;
        }
    }
    return ss.str();
}

std::string BoolToStr(bool v) {
    return v ? "true" : "false";
}
