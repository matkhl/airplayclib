#include "string_utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <sstream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace airplayc::utils {

std::string trim(std::string value) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::vector<std::string> split_lines(const std::string& value) {
    std::vector<std::string> lines;
    std::string current;
    std::istringstream input(value);
    while (std::getline(input, current)) {
        if (!current.empty() && current.back() == '\r') {
            current.pop_back();
        }
        lines.push_back(current);
    }
    return lines;
}

std::string hex_encode(const uint8_t* data, size_t bytes) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes; ++i) {
        out << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return out.str();
}

bool hex_decode(const std::string& hex, std::vector<uint8_t>& bytes) {
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return 10 + ch - 'a';
        }
        if (ch >= 'A' && ch <= 'F') {
            return 10 + ch - 'A';
        }
        return -1;
    };

    if ((hex.size() % 2) != 0) {
        return false;
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    bytes = std::move(out);
    return true;
}

std::string stable_device_id(const std::string& seed) {
    // FNV-1a expanded to 16 hex bytes. This is a stable local identifier, not a
    // cryptographic identity.
    uint64_t hash = 1469598103934665603ull;
    for (unsigned char c : seed) {
        hash ^= c;
        hash *= 1099511628211ull;
    }

    std::array<uint8_t, 16> bytes{};
    for (size_t i = 0; i < 8; ++i) {
        bytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xff);
        bytes[i + 8] = static_cast<uint8_t>(((hash ^ 0xa5a5a5a5a5a5a5a5ull) >> (i * 8)) & 0xff);
    }
    return hex_encode(bytes.data(), bytes.size());
}

std::wstring widen(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int required = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (required <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), required);
    return result;
}

} // namespace airplayc::utils
