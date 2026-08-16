#pragma once

#include <map>
#include <cstdint>
#include <string>
#include <vector>

namespace airplayc::plist {

using Dictionary = std::map<std::string, std::string>;

struct Value {
    enum class Type {
        Null,
        Boolean,
        Integer,
        Real,
        String,
        Data,
        Array,
        Dictionary,
    };

    Type type = Type::Null;
    bool boolean = false;
    uint64_t integer = 0;
    double real = 0.0;
    std::string text;
    std::vector<uint8_t> data;
    std::vector<Value> array;
    std::map<std::string, Value> dict;

    const Value* get(const std::string& key) const;
};

Dictionary parse_loose_xml_dictionary(const std::string& xml);
std::string make_xml_dictionary(const Dictionary& values);
bool parse_binary_plist(const std::string& data, Value& root, std::string& error);
std::string describe_binary_plist(const std::string& data);

} // namespace airplayc::plist
