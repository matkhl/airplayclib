#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace airplayc::utils {

std::string trim(std::string value);
std::string to_lower(std::string value);
std::vector<std::string> split_lines(const std::string& value);
std::string hex_encode(const uint8_t* data, size_t bytes);
bool hex_decode(const std::string& hex, std::vector<uint8_t>& bytes);
std::string stable_device_id(const std::string& seed);
std::wstring widen(const std::string& value);

} // namespace airplayc::utils
