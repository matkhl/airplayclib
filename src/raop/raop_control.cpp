#include "raop_control.h"

#include "../plist/plist.h"
#include "../utils/string_utils.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <locale>
#include <map>
#include <optional>
#include <sstream>
#include <string_view>

namespace airplayc::raop {
namespace {

constexpr uint32_t kFeaturesNoLegacyPairing = 0x527FFEE6;
constexpr std::array<uint8_t, 12> kFpHandshakeHeader{
    0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14};

constexpr std::array<uint8_t, 142> kFpSetupV2Reply{
    0x46, 0x50, 0x4c, 0x59, 0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82, 0x02, 0x02, 0x2f, 0x7b,
    0x69, 0xe6, 0xb2, 0x7e, 0xbb, 0xf0, 0x68, 0x5f, 0x98, 0x54, 0x7f, 0x37, 0xce, 0xcf, 0x87, 0x06,
    0x99, 0x6e, 0x7e, 0x6b, 0x0f, 0xb2, 0xfa, 0x71, 0x20, 0x53, 0xe3, 0x94, 0x83, 0xda, 0x22, 0xc7,
    0x83, 0xa0, 0x72, 0x40, 0x4d, 0xdd, 0x41, 0xaa, 0x3d, 0x4c, 0x6e, 0x30, 0x22, 0x55, 0xaa, 0xa2,
    0xda, 0x1e, 0xb4, 0x77, 0x83, 0x8c, 0x79, 0xd5, 0x65, 0x17, 0xc3, 0xfa, 0x01, 0x54, 0x33, 0x9e,
    0xe3, 0x82, 0x9f, 0x30, 0xf0, 0xa4, 0x8f, 0x76, 0xdf, 0x77, 0x11, 0x7e, 0x56, 0x9e, 0xf3, 0x95,
    0xe8, 0xe2, 0x13, 0xb3, 0x1e, 0xb6, 0x70, 0xec, 0x5a, 0x8a, 0xf2, 0x6a, 0xfc, 0xbc, 0x89, 0x31,
    0xe6, 0x7e, 0xe8, 0xb9, 0xc5, 0xf2, 0xc7, 0x1d, 0x78, 0xf3, 0xef, 0x8d, 0x61, 0xf7, 0x3b, 0xcc,
    0x17, 0xc3, 0x40, 0x23, 0x52, 0x4a, 0x8b, 0x9c, 0xb1, 0x75, 0x05, 0x66, 0xe6, 0xb3};

constexpr std::array<std::array<uint8_t, 142>, 4> kFpSetupReplies{{
    {0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82, 0x02, 0x00, 0x0f, 0x9f,
     0x3f, 0x9e, 0x0a, 0x25, 0x21, 0xdb, 0xdf, 0x31, 0x2a, 0xb2, 0xbf, 0xb2, 0x9e, 0x8d, 0x23, 0x2b,
     0x63, 0x76, 0xa8, 0xc8, 0x18, 0x70, 0x1d, 0x22, 0xae, 0x93, 0xd8, 0x27, 0x37, 0xfe, 0xaf, 0x9d,
     0xb4, 0xfd, 0xf4, 0x1c, 0x2d, 0xba, 0x9d, 0x1f, 0x49, 0xca, 0xaa, 0xbf, 0x65, 0x91, 0xac, 0x1f,
     0x7b, 0xc6, 0xf7, 0xe0, 0x66, 0x3d, 0x21, 0xaf, 0xe0, 0x15, 0x65, 0x95, 0x3e, 0xab, 0x81, 0xf4,
     0x18, 0xce, 0xed, 0x09, 0x5a, 0xdb, 0x7c, 0x3d, 0x0e, 0x25, 0x49, 0x09, 0xa7, 0x98, 0x31, 0xd4,
     0x9c, 0x39, 0x82, 0x97, 0x34, 0x34, 0xfa, 0xcb, 0x42, 0xc6, 0x3a, 0x1c, 0xd9, 0x11, 0xa6, 0xfe,
     0x94, 0x1a, 0x8a, 0x6d, 0x4a, 0x74, 0x3b, 0x46, 0xc3, 0xa7, 0x64, 0x9e, 0x44, 0xc7, 0x89, 0x55,
     0xe4, 0x9d, 0x81, 0x55, 0x00, 0x95, 0x49, 0xc4, 0xe2, 0xf7, 0xa3, 0xf6, 0xd5, 0xba},
    {0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82, 0x02, 0x01, 0xcf, 0x32,
     0xa2, 0x57, 0x14, 0xb2, 0x52, 0x4f, 0x8a, 0xa0, 0xad, 0x7a, 0xf1, 0x64, 0xe3, 0x7b, 0xcf, 0x44,
     0x24, 0xe2, 0x00, 0x04, 0x7e, 0xfc, 0x0a, 0xd6, 0x7a, 0xfc, 0xd9, 0x5d, 0xed, 0x1c, 0x27, 0x30,
     0xbb, 0x59, 0x1b, 0x96, 0x2e, 0xd6, 0x3a, 0x9c, 0x4d, 0xed, 0x88, 0xba, 0x8f, 0xc7, 0x8d, 0xe6,
     0x4d, 0x91, 0xcc, 0xfd, 0x5c, 0x7b, 0x56, 0xda, 0x88, 0xe3, 0x1f, 0x5c, 0xce, 0xaf, 0xc7, 0x43,
     0x19, 0x95, 0xa0, 0x16, 0x65, 0xa5, 0x4e, 0x19, 0x39, 0xd2, 0x5b, 0x94, 0xdb, 0x64, 0xb9, 0xe4,
     0x5d, 0x8d, 0x06, 0x3e, 0x1e, 0x6a, 0xf0, 0x7e, 0x96, 0x56, 0x16, 0x2b, 0x0e, 0xfa, 0x40, 0x42,
     0x75, 0xea, 0x5a, 0x44, 0xd9, 0x59, 0x1c, 0x72, 0x56, 0xb9, 0xfb, 0xe6, 0x51, 0x38, 0x98, 0xb8,
     0x02, 0x27, 0x72, 0x19, 0x88, 0x57, 0x16, 0x50, 0x94, 0x2a, 0xd9, 0x46, 0x68, 0x8a},
    {0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82, 0x02, 0x02, 0xc1, 0x69,
     0xa3, 0x52, 0xee, 0xed, 0x35, 0xb1, 0x8c, 0xdd, 0x9c, 0x58, 0xd6, 0x4f, 0x16, 0xc1, 0x51, 0x9a,
     0x89, 0xeb, 0x53, 0x17, 0xbd, 0x0d, 0x43, 0x36, 0xcd, 0x68, 0xf6, 0x38, 0xff, 0x9d, 0x01, 0x6a,
     0x5b, 0x52, 0xb7, 0xfa, 0x92, 0x16, 0xb2, 0xb6, 0x54, 0x82, 0xc7, 0x84, 0x44, 0x11, 0x81, 0x21,
     0xa2, 0xc7, 0xfe, 0xd8, 0x3d, 0xb7, 0x11, 0x9e, 0x91, 0x82, 0xaa, 0xd7, 0xd1, 0x8c, 0x70, 0x63,
     0xe2, 0xa4, 0x57, 0x55, 0x59, 0x10, 0xaf, 0x9e, 0x0e, 0xfc, 0x76, 0x34, 0x7d, 0x16, 0x40, 0x43,
     0x80, 0x7f, 0x58, 0x1e, 0xe4, 0xfb, 0xe4, 0x2c, 0xa9, 0xde, 0xdc, 0x1b, 0x5e, 0xb2, 0xa3, 0xaa,
     0x3d, 0x2e, 0xcd, 0x59, 0xe7, 0xee, 0xe7, 0x0b, 0x36, 0x29, 0xf2, 0x2a, 0xfd, 0x16, 0x1d, 0x87,
     0x73, 0x53, 0xdd, 0xb9, 0x9a, 0xdc, 0x8e, 0x07, 0x00, 0x6e, 0x56, 0xf8, 0x50, 0xce},
    {0x46, 0x50, 0x4c, 0x59, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x82, 0x02, 0x03, 0x90, 0x01,
     0xe1, 0x72, 0x7e, 0x0f, 0x57, 0xf9, 0xf5, 0x88, 0x0d, 0xb1, 0x04, 0xa6, 0x25, 0x7a, 0x23, 0xf5,
     0xcf, 0xff, 0x1a, 0xbb, 0xe1, 0xe9, 0x30, 0x45, 0x25, 0x1a, 0xfb, 0x97, 0xeb, 0x9f, 0xc0, 0x01,
     0x1e, 0xbe, 0x0f, 0x3a, 0x81, 0xdf, 0x5b, 0x69, 0x1d, 0x76, 0xac, 0xb2, 0xf7, 0xa5, 0xc7, 0x08,
     0xe3, 0xd3, 0x28, 0xf5, 0x6b, 0xb3, 0x9d, 0xbd, 0xe5, 0xf2, 0x9c, 0x8a, 0x17, 0xf4, 0x81, 0x48,
     0x7e, 0x3a, 0xe8, 0x63, 0xc6, 0x78, 0x32, 0x54, 0x22, 0xe6, 0xf7, 0x8e, 0x16, 0x6d, 0x18, 0xaa,
     0x7f, 0xd6, 0x36, 0x25, 0x8b, 0xce, 0x28, 0x72, 0x6f, 0x66, 0x1f, 0x73, 0x88, 0x93, 0xce, 0x44,
     0x31, 0x1e, 0x4b, 0xe6, 0xc0, 0x53, 0x51, 0x93, 0xe5, 0xef, 0x72, 0xe8, 0x68, 0x62, 0x33, 0x72,
     0x9c, 0x22, 0x7d, 0x82, 0x0c, 0x99, 0x94, 0x45, 0xd8, 0x92, 0x46, 0xc8, 0xc3, 0x59},
}};

std::string bytes_to_string(const uint8_t* data, size_t size) {
    return std::string(reinterpret_cast<const char*>(data), size);
}

void append_u16_be(std::string& out, uint16_t value) {
    out.push_back(static_cast<char>((value >> 8) & 0xff));
    out.push_back(static_cast<char>(value & 0xff));
}

void append_u64_be(std::string& out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<char>((value >> shift) & 0xff));
    }
}

void append_bplist_length(std::string& out, uint8_t marker, size_t length) {
    if (length < 15) {
        out.push_back(static_cast<char>(marker | static_cast<uint8_t>(length)));
        return;
    }

    out.push_back(static_cast<char>(marker | 0x0f));
    if (length <= 0xff) {
        out.push_back(0x10);
        out.push_back(static_cast<char>(length));
    } else {
        out.push_back(0x11);
        append_u16_be(out, static_cast<uint16_t>(length));
    }
}

std::string bplist_ascii(const char* value) {
    std::string out;
    const std::string_view text(value);
    append_bplist_length(out, 0x50, text.size());
    out.append(text);
    return out;
}

std::string bplist_uint(uint16_t value) {
    std::string out;
    out.push_back(0x11);
    append_u16_be(out, value);
    return out;
}

std::string lower_ascii(std::string value);

bool parse_volume_parameter(const std::string& body, float& volume_db) {
    constexpr std::string_view prefix = "volume:";
    const std::string lower_body = lower_ascii(body);
    const size_t found = lower_body.find(prefix);
    if (found == std::string::npos) {
        return false;
    }

    const size_t value_start = found + prefix.size();
    std::string value = utils::trim(body.substr(value_start));
    const size_t line_end = value.find_first_of("\r\n");
    if (line_end != std::string::npos) {
        value.resize(line_end);
    }

    const auto* first = value.data();
    const auto* last = value.data() + value.size();
    const auto result = std::from_chars(first, last, volume_db);
    return result.ec == std::errc{} && result.ptr != first;
}

std::string lower_ascii(std::string value) {
    for (char& c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return value;
}

bool key_looks_like_volume(const std::string& key) {
    const std::string lower = lower_ascii(key);
    return lower == "volume" ||
           lower == "devicevolume" ||
           lower == "device-volume" ||
           lower == "outputvolume" ||
           lower == "outputdevicevolume" ||
           lower == "dmcp.device-volume" ||
           lower == "volumelevel" ||
           lower == "level";
}

std::optional<float> plist_number_to_volume_db(const plist::Value& value) {
    double n = 0.0;
    if (value.type == plist::Value::Type::Real) {
        n = value.real;
    } else if (value.type == plist::Value::Type::Integer) {
        n = static_cast<double>(value.integer);
    } else {
        return std::nullopt;
    }
    if (!std::isfinite(n)) return std::nullopt;

    if (n >= -30.0 && n <= 0.0) {
        return static_cast<float>(n);
    }
    if (n >= 0.0 && n <= 1.0) {
        return static_cast<float>((n - 1.0) * 30.0);
    }
    if (n > 1.0 && n <= 100.0) {
        return static_cast<float>((n / 100.0 - 1.0) * 30.0);
    }
    return std::nullopt;
}

bool find_volume_in_plist(const plist::Value& value, float& volume_db) {
    if (value.type == plist::Value::Type::Dictionary) {
        for (const auto& [key, child] : value.dict) {
            if (!key_looks_like_volume(key)) continue;
            if (auto db = plist_number_to_volume_db(child)) {
                volume_db = *db;
                return true;
            }
        }
        for (const auto& [key, child] : value.dict) {
            (void)key;
            if (find_volume_in_plist(child, volume_db)) return true;
        }
    } else if (value.type == plist::Value::Type::Array) {
        for (const auto& child : value.array) {
            if (find_volume_in_plist(child, volume_db)) return true;
        }
    }
    return false;
}

bool parse_binary_plist_volume(const std::string& body, float& volume_db) {
    if (body.compare(0, 8, "bplist00") != 0) return false;
    plist::Value root;
    std::string error;
    return plist::parse_binary_plist(body, root, error) &&
           find_volume_in_plist(root, volume_db);
}

bool parse_u64_decimal(std::string_view text, uint64_t& value) {
    const auto* first = text.data();
    const auto* last = text.data() + text.size();
    const auto result = std::from_chars(first, last, value);
    return result.ec == std::errc{} && result.ptr == last;
}

uint32_t first_feature_word_or(std::string_view features, uint32_t fallback) {
    const size_t comma = features.find(',');
    if (comma != std::string_view::npos) {
        features = features.substr(0, comma);
    }
    if (features.empty()) {
        return fallback;
    }

    int base = 10;
    if (features.size() > 2 && features[0] == '0' && (features[1] == 'x' || features[1] == 'X')) {
        features.remove_prefix(2);
        base = 16;
    }
    uint32_t value = 0;
    const auto result = std::from_chars(features.data(), features.data() + features.size(), value, base);
    return result.ec == std::errc{} && result.ptr == features.data() + features.size()
        ? value
        : fallback;
}

bool parse_progress_parameter(const std::string& body,
                              uint64_t sample_rate,
                              PlaybackProgress& progress) {
    constexpr std::string_view prefix = "progress:";
    const size_t found = body.find(prefix);
    if (found == std::string::npos) {
        return false;
    }

    std::string value = utils::trim(body.substr(found + prefix.size()));
    const size_t line_end = value.find_first_of("\r\n");
    if (line_end != std::string::npos) {
        value.resize(line_end);
    }

    const size_t first_slash = value.find('/');
    const size_t second_slash = first_slash == std::string::npos
        ? std::string::npos
        : value.find('/', first_slash + 1);
    if (first_slash == std::string::npos || second_slash == std::string::npos) {
        return false;
    }

    uint64_t start = 0;
    uint64_t current = 0;
    uint64_t end = 0;
    if (!parse_u64_decimal(std::string_view(value).substr(0, first_slash), start) ||
        !parse_u64_decimal(std::string_view(value).substr(first_slash + 1, second_slash - first_slash - 1), current) ||
        !parse_u64_decimal(std::string_view(value).substr(second_slash + 1), end)) {
        return false;
    }

    progress.start_rtp_time = start;
    progress.current_rtp_time = current;
    progress.end_rtp_time = end;
    if (sample_rate != 0) {
        if (current >= start) {
            progress.position_seconds = static_cast<double>(current - start) /
                                        static_cast<double>(sample_rate);
        }
        if (end >= start) {
            progress.duration_seconds = static_cast<double>(end - start) /
                                        static_cast<double>(sample_rate);
        }
    }
    return true;
}

uint32_t read_u32_be(std::string_view data, size_t offset) {
    return (static_cast<uint32_t>(static_cast<uint8_t>(data[offset])) << 24) |
           (static_cast<uint32_t>(static_cast<uint8_t>(data[offset + 1])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(data[offset + 2])) << 8) |
           static_cast<uint32_t>(static_cast<uint8_t>(data[offset + 3]));
}

void parse_dmap_items(std::string_view data, Metadata& metadata, size_t depth = 0) {
    if (depth > 8) {
        return;
    }

    size_t pos = 0;
    while (pos + 8 <= data.size()) {
        const std::string tag(data.substr(pos, 4));
        const uint32_t len = read_u32_be(data, pos + 4);
        pos += 8;
        if (pos + len > data.size()) {
            return;
        }

        const auto value = data.substr(pos, len);
        if (tag == "minm") {
            metadata.title.assign(value);
        } else if (tag == "asar") {
            metadata.artist.assign(value);
        } else if (tag == "asal") {
            metadata.album.assign(value);
        } else if (tag == "asgn") {
            metadata.genre.assign(value);
        } else if (tag == "mlit" || tag == "mdcl") {
            parse_dmap_items(value, metadata, depth + 1);
        }
        pos += len;
    }
}

Metadata parse_dmap_metadata(const std::string& body) {
    Metadata metadata;
    parse_dmap_items(std::string_view(body), metadata);
    return metadata;
}

int base64_value(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return 26 + ch - 'a';
    }
    if (ch >= '0' && ch <= '9') {
        return 52 + ch - '0';
    }
    if (ch == '+') {
        return 62;
    }
    if (ch == '/') {
        return 63;
    }
    return -1;
}

bool base64_decode(std::string_view text, std::vector<uint8_t>& bytes) {
    bytes.clear();
    uint32_t accumulator = 0;
    int bits = 0;
    for (const char ch : text) {
        if (ch == '=') {
            break;
        }
        if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') {
            continue;
        }
        const int value = base64_value(ch);
        if (value < 0) {
            return false;
        }
        accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            bytes.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xff));
        }
    }
    return true;
}

std::map<std::string, std::string> parse_sdp_attributes(const std::string& body) {
    std::map<std::string, std::string> attributes;
    for (const auto& line : utils::split_lines(body)) {
        if (line.size() < 3 || line[0] != 'a' || line[1] != '=') {
            continue;
        }
        const size_t colon = line.find(':', 2);
        if (colon == std::string::npos) {
            attributes[line.substr(2)] = {};
        } else {
            attributes[line.substr(2, colon - 2)] = line.substr(colon + 1);
        }
    }
    return attributes;
}

bool parse_transport_port(const std::string& transport, const std::string& name, uint16_t& port) {
    const std::string key = name + "=";
    const size_t found = transport.find(key);
    if (found == std::string::npos) {
        return false;
    }
    const size_t start = found + key.size();
    size_t end = transport.find(';', start);
    if (end == std::string::npos) {
        end = transport.size();
    }
    uint32_t parsed = 0;
    const auto text = std::string_view(transport).substr(start, end - start);
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || parsed > 0xffff) {
        return false;
    }
    port = static_cast<uint16_t>(parsed);
    return true;
}

bool parse_announce_sdp(const std::string& body,
                        uint8_t fairplay_setup_mode,
                        const std::vector<uint8_t>& fairplay_key_message,
                        SessionCryptoInfo& crypto_info,
                        AudioStreamInfo& stream_info,
                        std::string& error) {
    const auto attrs = parse_sdp_attributes(body);
    const auto ekey_it = attrs.find("fpaeskey");
    const auto eiv_it = attrs.find("aesiv");
    if (ekey_it == attrs.end() || eiv_it == attrs.end()) {
        error = "ANNOUNCE SDP missing fpaeskey/aesiv";
        return false;
    }

    std::vector<uint8_t> ekey;
    std::vector<uint8_t> eiv;
    if (!base64_decode(ekey_it->second, ekey) || !base64_decode(eiv_it->second, eiv)) {
        error = "ANNOUNCE SDP has invalid base64 crypto fields";
        return false;
    }
    if (ekey.empty() || eiv.empty()) {
        error = "ANNOUNCE SDP crypto fields decoded empty";
        return false;
    }

    crypto_info = {};
    crypto_info.encryption_type = 32;
    crypto_info.fairplay_setup_mode = fairplay_setup_mode;
    crypto_info.eiv = std::move(eiv);
    crypto_info.ekey = std::move(ekey);
    crypto_info.fairplay_key_message = fairplay_key_message;
    crypto_info.raw_setup_plist.assign(body.begin(), body.end());

    stream_info = {};
    stream_info.audio_format = 262144;
    stream_info.compression_type = 2;
    stream_info.sample_rate = 44100;
    stream_info.samples_per_frame = 352;
    stream_info.payload_type = 96;
    stream_info.audio_mode = "default";
    stream_info.raw_setup_plist.assign(body.begin(), body.end());

    const auto fmtp = attrs.find("fmtp");
    if (fmtp != attrs.end()) {
        std::istringstream input(fmtp->second);
        uint64_t payload = 0;
        uint64_t spf = 0;
        uint64_t compatible = 0;
        uint64_t bits = 0;
        uint64_t history = 0;
        uint64_t pb = 0;
        uint64_t mb = 0;
        uint64_t channels = 0;
        uint64_t max_run = 0;
        uint64_t max_frame = 0;
        uint64_t average_bit_rate = 0;
        uint64_t sample_rate = 0;
        input >> payload >> spf >> compatible >> bits >> history >> pb >> mb >>
            channels >> max_run >> max_frame >> average_bit_rate >> sample_rate;
        if (payload != 0) {
            stream_info.payload_type = payload;
        }
        if (spf != 0) {
            stream_info.samples_per_frame = spf;
        }
        if (sample_rate != 0) {
            stream_info.sample_rate = sample_rate;
        }
    }
    return true;
}

bool looks_like_stream_setup_request(const rtsp::Request& request) {
    if (request.header("Content-Type").find("application/x-apple-binary-plist") == std::string::npos) {
        return false;
    }
    return request.body.find("streams") != std::string::npos &&
           request.body.find("audioFormat") != std::string::npos;
}

uint64_t plist_uint_or(const plist::Value* value, uint64_t fallback = 0) {
    if (!value) {
        return fallback;
    }
    if (value->type == plist::Value::Type::Integer) {
        return value->integer;
    }
    if (value->type == plist::Value::Type::Boolean) {
        return value->boolean ? 1 : 0;
    }
    return fallback;
}

std::string plist_string_or(const plist::Value* value) {
    return value && value->type == plist::Value::Type::String ? value->text : std::string{};
}

std::vector<uint8_t> plist_data_or_empty(const plist::Value* value) {
    return value && value->type == plist::Value::Type::Data ? value->data : std::vector<uint8_t>{};
}

bool parse_session_crypto_info(const std::string& body,
                               uint8_t fairplay_setup_mode,
                               const std::vector<uint8_t>& fairplay_key_message,
                               SessionCryptoInfo& info,
                               std::string& error) {
    plist::Value root;
    if (!plist::parse_binary_plist(body, root, error)) {
        return false;
    }
    if (root.type != plist::Value::Type::Dictionary) {
        error = "session setup plist root is not a dictionary";
        return false;
    }

    const auto eiv = plist_data_or_empty(root.get("eiv"));
    const auto ekey = plist_data_or_empty(root.get("ekey"));
    const auto group_encryption_key = plist_data_or_empty(root.get("groupEncryptionKey"));
    if (eiv.empty() && ekey.empty() && group_encryption_key.empty()) {
        error = "session setup plist has no eiv/ekey/groupEncryptionKey";
        return false;
    }

    info.encryption_type = plist_uint_or(root.get("et"));
    info.fairplay_setup_mode = fairplay_setup_mode;
    info.timing_port = static_cast<uint16_t>(plist_uint_or(root.get("timingPort")));
    info.session_uuid = plist_string_or(root.get("sessionUUID"));
    info.source_version = plist_string_or(root.get("sourceVersion"));
    info.eiv = eiv;
    info.ekey = ekey;
    info.group_encryption_key = group_encryption_key;
    info.fairplay_key_message = fairplay_key_message;
    info.raw_setup_plist.assign(body.begin(), body.end());
    return true;
}

bool parse_audio_stream_info(const std::string& body, AudioStreamInfo& info, std::string& error) {
    plist::Value root;
    if (!plist::parse_binary_plist(body, root, error)) {
        return false;
    }
    const auto streams = root.get("streams");
    if (!streams || streams->type != plist::Value::Type::Array || streams->array.empty()) {
        error = "stream setup plist has no streams array";
        return false;
    }
    const auto& stream = streams->array.front();
    if (stream.type != plist::Value::Type::Dictionary) {
        error = "stream setup plist stream item is not a dictionary";
        return false;
    }

    info.audio_format = plist_uint_or(stream.get("audioFormat"));
    info.compression_type = plist_uint_or(stream.get("ct"));
    info.sample_rate = plist_uint_or(stream.get("sr"));
    info.samples_per_frame = plist_uint_or(stream.get("spf"));
    info.payload_type = plist_uint_or(stream.get("type"));
    info.client_control_port = static_cast<uint16_t>(plist_uint_or(stream.get("controlPort")));
    info.audio_mode = plist_string_or(stream.get("audioMode"));
    info.shared_key = plist_data_or_empty(stream.get("shk"));
    info.raw_setup_plist.assign(body.begin(), body.end());
    return info.audio_format != 0 || info.payload_type != 0;
}

std::string describe_session_crypto_info(const SessionCryptoInfo& info) {
    std::ostringstream out;
    out << "session crypto et=" << info.encryption_type
        << " fpMode=" << info.fairplay_setup_mode
        << " eiv=" << info.eiv.size() << " bytes"
        << " ekey=" << info.ekey.size() << " bytes";
    if (!info.group_encryption_key.empty()) {
        out << " groupKey=" << info.group_encryption_key.size() << " bytes";
    }
    if (!info.fairplay_key_message.empty()) {
        out << " fpKeyMsg=" << info.fairplay_key_message.size() << " bytes";
    }
    if (info.timing_port != 0) {
        out << " clientTimingPort=" << info.timing_port;
    }
    if (!info.source_version.empty()) {
        out << " sourceVersion=" << info.source_version;
    }
    return out.str();
}

std::string describe_audio_stream_info(const AudioStreamInfo& info) {
    std::ostringstream out;
    out << "audio stream format=" << info.audio_format
        << " ct=" << info.compression_type
        << " sr=" << info.sample_rate
        << " spf=" << info.samples_per_frame
        << " type=" << info.payload_type;
    if (info.client_control_port != 0) {
        out << " clientControlPort=" << info.client_control_port;
    }
    if (!info.audio_mode.empty()) {
        out << " mode=" << info.audio_mode;
    }
    if (!info.shared_key.empty()) {
        out << " shk=" << info.shared_key.size() << " bytes";
    }
    return out.str();
}

std::string format_volume_db(float db) {
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::fixed << std::setprecision(6) << db;
    return out.str();
}

} // namespace

ControlSession::ControlSession(ReceiverInfo info, ControlCallbacks callbacks)
    : info_(std::move(info)),
      callbacks_(std::move(callbacks)),
      current_volume_db_(info_.initial_volume_db) {}

void ControlSession::set_current_volume(float volume_db) {
    if (!std::isfinite(volume_db)) {
        return;
    }
    current_volume_db_ = std::clamp(volume_db, -30.0f, 0.0f);
    if (callbacks_.on_volume_changed) {
        callbacks_.on_volume_changed(current_volume_db_);
    }
}

rtsp::Response ControlSession::handle(const rtsp::Request& request) {
    if (callbacks_.on_protocol) {
        callbacks_.on_protocol(request_trace(request));
    }

    auto response = rtsp::make_response(request);

    if (request.method == "OPTIONS") {
        response.headers["Public"] = "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER";
        response.body = options_body();
        response.headers["Content-Type"] = "text/parameters";
        return response;
    }

    if (request.method == "GET" && (request.uri == "/info" || request.uri.find("/info?") == 0)) {
        response.body = info_plist_body();
        response.headers["Content-Type"] = "application/x-apple-plist+xml";
        return response;
    }

    if (request.method == "POST" && request.uri == "/feedback") {
        return response;
    }

    if (request.method == "POST" && request.uri == "/command") {
        float volume_db = 0.0f;
        if (request.body.compare(0, 8, "bplist00") == 0 &&
            parse_binary_plist_volume(request.body, volume_db)) {
            set_current_volume(volume_db);
            if (callbacks_.on_protocol) {
                callbacks_.on_protocol("POST /command volume: " +
                                       format_volume_db(current_volume_db_));
            }
        }
        if (callbacks_.on_protocol) {
            callbacks_.on_protocol("media remote command update accepted");
        }
        return response;
    }

    if (request.method == "POST" && request.uri == "/audioMode") {
        if (request.header("Content-Type").find("application/x-apple-binary-plist") != std::string::npos &&
            callbacks_.on_protocol) {
            callbacks_.on_protocol("audioMode update accepted");
        }
        return response;
    }

    if (request.method == "POST" && request.uri == "/fp-setup") {
        return handle_fp_setup(request);
    }

    if (request.method == "POST" &&
        (request.uri == "/pair-setup" || request.uri == "/pair-verify" ||
         request.uri == "/pair-setup-pin")) {
        if (callbacks_.on_error) {
            callbacks_.on_error("Pairing endpoint reached but not implemented yet: " + request.uri);
        }
        return rtsp::make_response(request, 501, "Not Implemented");
    }

    if (request.method == "GET_PARAMETER") {
        response.body = server_info_body();
        response.headers["Content-Type"] = "text/parameters";
        return response;
    }

    if (request.method == "ANNOUNCE") {
        if (request.header("Content-Type").find("application/sdp") != std::string::npos) {
            SessionCryptoInfo crypto_info;
            AudioStreamInfo stream_info;
            std::string parse_error;
            if (parse_announce_sdp(request.body,
                                   last_fp_setup_mode_,
                                   last_fp_setup_key_message_,
                                   crypto_info,
                                   stream_info,
                                   parse_error)) {
                announced_crypto_ = crypto_info;
                announced_stream_ = stream_info;
                have_announced_crypto_ = true;
                have_announced_stream_ = true;
                stream_sample_rate_ = stream_info.sample_rate == 0 ? 44100 : stream_info.sample_rate;
                if (callbacks_.on_session_crypto) {
                    callbacks_.on_session_crypto(crypto_info);
                }
                if (callbacks_.on_protocol) {
                    callbacks_.on_protocol("ANNOUNCE SDP " + describe_session_crypto_info(crypto_info));
                }
            } else if (callbacks_.on_error) {
                callbacks_.on_error("failed to parse ANNOUNCE SDP: " + parse_error);
            }
        }
        response.body.clear();
        return response;
    }

    if (request.method == "SETUP") {
        response.headers["Transport"] = request.header("Transport");
        response.headers["Session"] = "1";
        if (looks_like_stream_setup_request(request)) {
            AudioStreamInfo stream_info;
            std::string parse_error;
            if (parse_audio_stream_info(request.body, stream_info, parse_error)) {
                if (stream_info.sample_rate != 0) {
                    stream_sample_rate_ = stream_info.sample_rate;
                }
                if (callbacks_.on_audio_stream) {
                    callbacks_.on_audio_stream(stream_info);
                }
                if (callbacks_.on_protocol) {
                    callbacks_.on_protocol(describe_audio_stream_info(stream_info));
                }
            } else if (callbacks_.on_error) {
                callbacks_.on_error("failed to parse audio stream setup plist: " + parse_error);
            }
            response.body = stream_setup_response_body();
            response.headers["Content-Type"] = "application/x-apple-binary-plist";
            response.headers.erase("Transport");
            if (callbacks_.on_protocol) {
                callbacks_.on_protocol("SETUP audio stream ports data=" +
                                       std::to_string(info_.audio_data_port) +
                                       " control=" + std::to_string(info_.audio_control_port) +
                                       " timing=" + std::to_string(info_.timing_port));
            }
        } else if (have_announced_stream_ && !request.header("Transport").empty()) {
            const auto transport = request.header("Transport");
            AudioStreamInfo stream_info = announced_stream_;
            parse_transport_port(transport, "control_port", stream_info.client_control_port);
            stream_info.raw_setup_plist.assign(transport.begin(), transport.end());
            if (callbacks_.on_audio_stream) {
                callbacks_.on_audio_stream(stream_info);
            }
            if (callbacks_.on_protocol) {
                callbacks_.on_protocol(describe_audio_stream_info(stream_info));
            }
            response.headers["Transport"] =
                "RTP/AVP/UDP;unicast;mode=record;server_port=" +
                std::to_string(info_.audio_data_port) +
                ";control_port=" + std::to_string(info_.audio_control_port) +
                ";timing_port=" + std::to_string(info_.timing_port);
            if (callbacks_.on_protocol) {
                callbacks_.on_protocol("SETUP classic RAOP ports data=" +
                                       std::to_string(info_.audio_data_port) +
                                       " control=" + std::to_string(info_.audio_control_port) +
                                       " timing=" + std::to_string(info_.timing_port));
            }
        } else if (request.header("Content-Type").find("application/x-apple-binary-plist") != std::string::npos) {
            SessionCryptoInfo crypto_info;
            std::string parse_error;
            if (parse_session_crypto_info(request.body,
                                          last_fp_setup_mode_,
                                          last_fp_setup_key_message_,
                                          crypto_info,
                                          parse_error)) {
                if (callbacks_.on_session_crypto) {
                    callbacks_.on_session_crypto(crypto_info);
                }
                if (callbacks_.on_protocol) {
                    callbacks_.on_protocol(describe_session_crypto_info(crypto_info));
                }
            }
        }
        return response;
    }

    if (request.method == "RECORD") {
        if (!playback_active_ && callbacks_.on_playback_started) {
            callbacks_.on_playback_started();
        }
        playback_active_ = true;
        response.headers["Audio-Latency"] = "11025";
        return response;
    }

    if (request.method == "PAUSE") {
        if (callbacks_.on_playback_paused) {
            callbacks_.on_playback_paused();
        }
        return response;
    }

    if (request.method == "FLUSH") {
        if (callbacks_.on_protocol) {
            callbacks_.on_protocol("FLUSH buffer reset");
        }
        return response;
    }

    if (request.method == "TEARDOWN") {
        if (callbacks_.on_playback_stopped) {
            callbacks_.on_playback_stopped();
        }
        playback_active_ = false;
        return response;
    }

    if (request.method == "SET_PARAMETER") {
        if (request.header("Content-Type").find("text/parameters") != std::string::npos) {
            float volume_db = 0.0f;
            if (parse_volume_parameter(request.body, volume_db)) {
                set_current_volume(volume_db);
            }
            PlaybackProgress progress;
            if (parse_progress_parameter(request.body, stream_sample_rate_, progress) && callbacks_.on_progress) {
                callbacks_.on_progress(progress);
            }
            if (callbacks_.on_protocol) {
                callbacks_.on_protocol("SET_PARAMETER body: " + request.body);
            }
        } else if (request.header("Content-Type").find("application/x-apple-binary-plist") != std::string::npos) {
            float volume_db = 0.0f;
            if (parse_binary_plist_volume(request.body, volume_db)) {
                set_current_volume(volume_db);
                if (callbacks_.on_protocol) {
                    callbacks_.on_protocol("SET_PARAMETER binary plist volume: " +
                                           format_volume_db(current_volume_db_));
                }
            }
        } else if (request.header("Content-Type") == "application/x-dmap-tagged") {
            const auto metadata = parse_dmap_metadata(request.body);
            if (callbacks_.on_metadata &&
                (!metadata.title.empty() || !metadata.artist.empty() ||
                 !metadata.album.empty() || !metadata.genre.empty())) {
                callbacks_.on_metadata(metadata);
            }
        } else if (request.header("Content-Type") == "image/jpeg" ||
                   request.header("Content-Type") == "image/png") {
            if (callbacks_.on_cover_art && !request.body.empty()) {
                callbacks_.on_cover_art(reinterpret_cast<const uint8_t*>(request.body.data()),
                                        request.body.size(),
                                        request.header("Content-Type"));
            }
        }
        return response;
    }

    if (callbacks_.on_error) {
        callbacks_.on_error("Unsupported RTSP method: " + request.method);
    }
    return rtsp::make_response(request, 501, "Not Implemented");
}

std::string ControlSession::options_body() const {
    return "audioMode: true\r\n";
}

std::string ControlSession::server_info_body() const {
    std::ostringstream out;
    out << "audio-jack-status: connected; type=analog\r\n";
    out << "volume: " << format_volume_db(current_volume_db_) << "\r\n";
    return out.str();
}

std::string ControlSession::info_plist_body() const {
    const std::string mac = info_.device_id.size() >= 12
        ? info_.device_id.substr(0, 2) + ":" + info_.device_id.substr(2, 2) + ":" +
          info_.device_id.substr(4, 2) + ":" + info_.device_id.substr(6, 2) + ":" +
          info_.device_id.substr(8, 2) + ":" + info_.device_id.substr(10, 2)
        : "00:00:00:00:00:00";

    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ";
    out << "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    out << "<plist version=\"1.0\"><dict>\n";
    out << "<key>deviceID</key><string>" << mac << "</string>\n";
    out << "<key>macAddress</key><string>" << mac << "</string>\n";
    const std::string& info_features = info_.info_feature_flags.empty()
        ? info_.feature_flags
        : info_.info_feature_flags;
    out << "<key>features</key><integer>"
        << first_feature_word_or(info_features, kFeaturesNoLegacyPairing)
        << "</integer>\n";
    out << "<key>statusFlags</key><integer>68</integer>\n";
    out << "<key>name</key><string>" << info_.device_name << "</string>\n";
    out << "<key>manufacturer</key><string>" << info_.manufacturer << "</string>\n";
    out << "<key>model</key><string>" << info_.model << "</string>\n";
    if (!info_.firmware_version.empty()) {
        out << "<key>firmwareVersion</key><string>" << info_.firmware_version << "</string>\n";
    }
    out << "<key>sourceVersion</key><string>" << info_.source_version << "</string>\n";
    out << "<key>vv</key><integer>2</integer>\n";
    out << "<key>keepAliveLowPower</key><integer>1</integer>\n";
    out << "<key>keepAliveSendStatsAsBody</key><true/>\n";
    out << "<key>initialVolume</key><real>" << format_volume_db(info_.initial_volume_db) << "</real>\n";
    out << "<key>audioFormats</key><array><dict>";
    out << "<key>type</key><integer>100</integer>";
    out << "<key>audioInputFormats</key><integer>67108860</integer>";
    out << "<key>audioOutputFormats</key><integer>67108860</integer>";
    out << "</dict><dict>";
    out << "<key>type</key><integer>101</integer>";
    out << "<key>audioInputFormats</key><integer>67108860</integer>";
    out << "<key>audioOutputFormats</key><integer>67108860</integer>";
    out << "</dict></array>\n";
    out << "<key>audioLatencies</key><array><dict>";
    out << "<key>type</key><integer>100</integer>";
    out << "<key>audioType</key><string>default</string>";
    out << "<key>inputLatencyMicros</key><integer>0</integer>";
    out << "<key>outputLatencyMicros</key><integer>0</integer>";
    out << "</dict><dict>";
    out << "<key>type</key><integer>101</integer>";
    out << "<key>audioType</key><string>default</string>";
    out << "<key>inputLatencyMicros</key><integer>0</integer>";
    out << "<key>outputLatencyMicros</key><integer>0</integer>";
    out << "</dict></array>\n";
    out << "</dict></plist>\n";
    return out.str();
}

std::string ControlSession::stream_setup_response_body() const {
    // Minimal binary plist:
    // { streams = [ { dataPort = n; controlPort = n; type = 96; } ]; }
    const uint16_t data_port = info_.audio_data_port;
    const uint16_t control_port = info_.audio_control_port;

    std::array<std::string, 10> objects{
        std::string{},                       // root dict, filled below
        bplist_ascii("streams"),
        std::string{},                       // streams array, filled below
        std::string{},                       // stream dict, filled below
        bplist_ascii("dataPort"),
        bplist_ascii("controlPort"),
        bplist_ascii("type"),
        bplist_uint(data_port),
        bplist_uint(control_port),
        bplist_uint(96),
    };

    objects[0].push_back(static_cast<char>(0xd1));
    objects[0].push_back(1);
    objects[0].push_back(2);

    objects[2].push_back(static_cast<char>(0xa1));
    objects[2].push_back(3);

    objects[3].push_back(static_cast<char>(0xd3));
    objects[3].push_back(4);
    objects[3].push_back(5);
    objects[3].push_back(6);
    objects[3].push_back(7);
    objects[3].push_back(8);
    objects[3].push_back(9);

    std::string out = "bplist00";
    std::array<uint16_t, 10> offsets{};
    for (size_t i = 0; i < objects.size(); ++i) {
        offsets[i] = static_cast<uint16_t>(out.size());
        out.append(objects[i]);
    }

    const uint64_t offset_table_offset = out.size();
    for (const auto offset : offsets) {
        append_u16_be(out, offset);
    }

    out.append(6, '\0');
    out.push_back(0x02); // offset int size
    out.push_back(0x01); // object ref size
    append_u64_be(out, objects.size());
    append_u64_be(out, 0);
    append_u64_be(out, offset_table_offset);
    return out;
}

rtsp::Response ControlSession::handle_fp_setup(const rtsp::Request& request) {
    auto response = rtsp::make_response(request);
    response.headers["Content-Type"] = "application/octet-stream";

    const auto body = std::string_view(request.body);
    if (body.size() == 16 && body.substr(0, 4) == "FPLY") {
        const auto mode = static_cast<uint8_t>(body[14]);
        if (body[4] == 0x02) {
            auto reply = kFpSetupV2Reply;
            reply[13] = mode;
            last_fp_setup_mode_ = mode;
            response.body = bytes_to_string(reply.data(), reply.size());
            if (callbacks_.on_protocol) {
                callbacks_.on_protocol("fp-setup v2 setup reply requestMode=" + std::to_string(mode) +
                                       " bytes=" + std::to_string(reply.size()));
            }
            return response;
        }
        if (body[4] != 0x03 || mode >= kFpSetupReplies.size()) {
            if (callbacks_.on_error) {
                callbacks_.on_error("Unsupported fp-setup setup request version/mode");
            }
            return rtsp::make_response(request, 400, "Bad Request");
        }

        const auto& reply = kFpSetupReplies[mode];
        last_fp_setup_mode_ = mode;
        response.body = bytes_to_string(reply.data(), reply.size());
        if (callbacks_.on_protocol) {
            callbacks_.on_protocol("fp-setup setup reply mode=" + std::to_string(mode) +
                                   " bytes=" + std::to_string(reply.size()));
        }
        return response;
    }

    if (body.size() == 164 && body.substr(0, 4) == "FPLY") {
        if (body[4] != 0x03 && body[4] != 0x02) {
            if (callbacks_.on_error) {
                callbacks_.on_error("Unsupported fp-setup handshake request version");
            }
            return rtsp::make_response(request, 400, "Bad Request");
        }

        last_fp_setup_key_message_.assign(reinterpret_cast<const uint8_t*>(body.data()),
                                          reinterpret_cast<const uint8_t*>(body.data() + body.size()));
        response.body = bytes_to_string(kFpHandshakeHeader.data(), kFpHandshakeHeader.size());
        response.body.append(body.substr(144, 20));
        if (callbacks_.on_protocol) {
            callbacks_.on_protocol("fp-setup handshake reply version=" + std::to_string(static_cast<unsigned>(body[4])) +
                                   " bytes=" + std::to_string(response.body.size()));
        }
        return response;
    }

    if (callbacks_.on_error) {
        callbacks_.on_error("Invalid fp-setup data length: " + std::to_string(body.size()));
    }
    return rtsp::make_response(request, 400, "Bad Request");
}

std::string ControlSession::request_trace(const rtsp::Request& request) const {
    std::ostringstream out;
    out << request.method << ' ' << request.uri << " " << request.version;
    for (const auto& [name, value] : request.headers) {
        out << "\n  " << name << ": " << value;
    }
    out << "\n  body-bytes: " << request.body.size();
    if (!request.body.empty()) {
        const auto type = request.header("Content-Type");
        if (type.find("text/") != std::string::npos ||
            type.find("application/x-apple-plist+xml") != std::string::npos) {
            out << "\n  body-text: " << request.body.substr(0, 512);
        } else {
            size_t limit = request.body.size() < 1024 ? request.body.size() : 1024;
            if (type == "image/jpeg" || type == "image/png") {
                limit = request.body.size() < 64 ? request.body.size() : 64;
            } else if (request.body.size() > 8192) {
                limit = 256;
            }
            out << "\n  body-hex:";
            out << std::hex << std::setfill('0');
            for (size_t i = 0; i < limit; ++i) {
                out << ' ' << std::setw(2)
                    << static_cast<unsigned>(static_cast<unsigned char>(request.body[i]));
            }
            if (request.body.size() > limit) {
                out << " ...";
            }
            if (request.body.compare(0, 8, "bplist00") == 0) {
                const auto summary = plist::describe_binary_plist(request.body);
                if (!summary.empty()) {
                    out << '\n' << summary;
                }
            }
        }
    }
    return out.str();
}

} // namespace airplayc::raop
