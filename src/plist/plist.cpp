#include "plist.h"

#include "../utils/string_utils.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

namespace airplayc::plist {
namespace {

uint64_t read_be(const std::string& data, size_t offset, size_t bytes) {
    uint64_t value = 0;
    for (size_t i = 0; i < bytes && offset + i < data.size(); ++i) {
        value = (value << 8) | static_cast<unsigned char>(data[offset + i]);
    }
    return value;
}

class BinaryPlistDescriber {
public:
    explicit BinaryPlistDescriber(const std::string& data)
        : data_(data) {}

    std::string describe() {
        if (data_.size() < 40 || data_.compare(0, 8, "bplist00") != 0) {
            return {};
        }

        const size_t trailer = data_.size() - 32;
        offset_int_size_ = static_cast<uint8_t>(data_[trailer + 6]);
        object_ref_size_ = static_cast<uint8_t>(data_[trailer + 7]);
        const uint64_t object_count = read_be(data_, trailer + 8, 8);
        top_object_ = read_be(data_, trailer + 16, 8);
        const uint64_t offset_table = read_be(data_, trailer + 24, 8);
        if (offset_int_size_ == 0 || object_ref_size_ == 0 ||
            object_count > 4096 || offset_table >= data_.size()) {
            return "bplist: invalid trailer";
        }

        offsets_.reserve(static_cast<size_t>(object_count));
        for (uint64_t i = 0; i < object_count; ++i) {
            const size_t pos = static_cast<size_t>(offset_table + i * offset_int_size_);
            if (pos + offset_int_size_ > data_.size()) {
                return "bplist: truncated offset table";
            }
            offsets_.push_back(static_cast<size_t>(read_be(data_, pos, offset_int_size_)));
        }

        std::ostringstream out;
        out << "bplist-summary:\n";
        describe_object(top_object_, "$", out, 0);
        return out.str();
    }

private:
    size_t object_offset(uint64_t object) const {
        if (object >= offsets_.size()) {
            return std::string::npos;
        }
        return offsets_[static_cast<size_t>(object)];
    }

    uint64_t read_ref(size_t offset) const {
        return read_be(data_, offset, object_ref_size_);
    }

    bool read_count(size_t& offset, uint8_t low, uint64_t& count) const {
        if (low < 0x0f) {
            count = low;
            return true;
        }
        if (offset >= data_.size()) {
            return false;
        }
        const uint8_t marker = static_cast<uint8_t>(data_[offset++]);
        if ((marker >> 4) != 0x1) {
            return false;
        }
        const size_t bytes = size_t{1} << (marker & 0x0f);
        if (offset + bytes > data_.size()) {
            return false;
        }
        count = read_be(data_, offset, bytes);
        offset += bytes;
        return true;
    }

    std::string atom_to_string(uint64_t object) {
        const size_t start = object_offset(object);
        if (start == std::string::npos || start >= data_.size()) {
            return "<bad-ref>";
        }
        size_t offset = start + 1;
        const uint8_t marker = static_cast<uint8_t>(data_[start]);
        const uint8_t high = marker >> 4;
        const uint8_t low = marker & 0x0f;

        if (high == 0x5 || high == 0x6) {
            uint64_t count = 0;
            if (!read_count(offset, low, count)) {
                return "<bad-string>";
            }
            if (high == 0x5) {
                if (offset + count > data_.size()) {
                    return "<truncated-string>";
                }
                return data_.substr(offset, static_cast<size_t>(count));
            }
            if (offset + count * 2 > data_.size()) {
                return "<truncated-utf16>";
            }
            std::string ascii;
            for (uint64_t i = 0; i < count; ++i) {
                const auto ch = static_cast<char>(data_[offset + i * 2 + 1]);
                ascii.push_back(ch == '\0' ? '?' : ch);
            }
            return ascii;
        }

        if (high == 0x1) {
            const size_t bytes = size_t{1} << low;
            if (offset + bytes > data_.size()) {
                return "<truncated-int>";
            }
            return std::to_string(read_be(data_, offset, bytes));
        }

        if (high == 0x4) {
            uint64_t count = 0;
            if (!read_count(offset, low, count)) {
                return "<bad-data>";
            }
            if (offset + count > data_.size()) {
                return "<truncated-data>";
            }
            const size_t sample = std::min<size_t>(static_cast<size_t>(count), 48);
            std::ostringstream out;
            out << "data[" << count << "]=";
            out << utils::hex_encode(reinterpret_cast<const uint8_t*>(data_.data() + offset), sample);
            if (count > sample) {
                out << "...";
            }
            return out.str();
        }

        if (marker == 0x08) {
            return "false";
        }
        if (marker == 0x09) {
            return "true";
        }
        if (high == 0x2 && offset + (size_t{1} << low) <= data_.size()) {
            return "<real>";
        }
        return "<object>";
    }

    void describe_object(uint64_t object, const std::string& path, std::ostringstream& out, int depth) {
        if (depth > 8) {
            out << "  " << path << " = <max-depth>\n";
            return;
        }
        const size_t start = object_offset(object);
        if (start == std::string::npos || start >= data_.size()) {
            out << "  " << path << " = <bad-ref>\n";
            return;
        }

        size_t offset = start + 1;
        const uint8_t marker = static_cast<uint8_t>(data_[start]);
        const uint8_t high = marker >> 4;
        const uint8_t low = marker & 0x0f;

        if (high == 0xd) {
            uint64_t count = 0;
            if (!read_count(offset, low, count)) {
                out << "  " << path << " = <bad-dict>\n";
                return;
            }
            if (count > 128 || offset + count * object_ref_size_ * 2 > data_.size()) {
                out << "  " << path << " = <dict-too-large>\n";
                return;
            }
            const size_t keys = offset;
            const size_t vals = offset + static_cast<size_t>(count) * object_ref_size_;
            for (uint64_t i = 0; i < count; ++i) {
                const std::string key = atom_to_string(read_ref(keys + static_cast<size_t>(i) * object_ref_size_));
                describe_object(read_ref(vals + static_cast<size_t>(i) * object_ref_size_),
                                path + "." + key,
                                out,
                                depth + 1);
            }
            return;
        }

        if (high == 0xa) {
            uint64_t count = 0;
            if (!read_count(offset, low, count)) {
                out << "  " << path << " = <bad-array>\n";
                return;
            }
            if (count > 128 || offset + count * object_ref_size_ > data_.size()) {
                out << "  " << path << " = <array-too-large>\n";
                return;
            }
            for (uint64_t i = 0; i < count; ++i) {
                describe_object(read_ref(offset + static_cast<size_t>(i) * object_ref_size_),
                                path + "[" + std::to_string(i) + "]",
                                out,
                                depth + 1);
            }
            return;
        }

        out << "  " << path << " = " << atom_to_string(object) << "\n";
    }

    const std::string& data_;
    uint8_t offset_int_size_ = 0;
    uint8_t object_ref_size_ = 0;
    uint64_t top_object_ = 0;
    std::vector<size_t> offsets_;
};

class BinaryPlistParser {
public:
    explicit BinaryPlistParser(const std::string& data)
        : data_(data) {}

    bool parse(Value& root, std::string& error) {
        if (data_.size() < 40 || data_.compare(0, 8, "bplist00") != 0) {
            error = "not a binary plist";
            return false;
        }

        const size_t trailer = data_.size() - 32;
        offset_int_size_ = static_cast<uint8_t>(data_[trailer + 6]);
        object_ref_size_ = static_cast<uint8_t>(data_[trailer + 7]);
        const uint64_t object_count = read_be(data_, trailer + 8, 8);
        top_object_ = read_be(data_, trailer + 16, 8);
        const uint64_t offset_table = read_be(data_, trailer + 24, 8);
        if (offset_int_size_ == 0 || object_ref_size_ == 0 ||
            object_count > 4096 || offset_table >= data_.size()) {
            error = "invalid binary plist trailer";
            return false;
        }

        offsets_.reserve(static_cast<size_t>(object_count));
        for (uint64_t i = 0; i < object_count; ++i) {
            const size_t pos = static_cast<size_t>(offset_table + i * offset_int_size_);
            if (pos + offset_int_size_ > data_.size()) {
                error = "truncated binary plist offset table";
                return false;
            }
            offsets_.push_back(static_cast<size_t>(read_be(data_, pos, offset_int_size_)));
        }

        return parse_object(top_object_, root, error, 0);
    }

private:
    size_t object_offset(uint64_t object) const {
        if (object >= offsets_.size()) {
            return std::string::npos;
        }
        return offsets_[static_cast<size_t>(object)];
    }

    uint64_t read_ref(size_t offset) const {
        return read_be(data_, offset, object_ref_size_);
    }

    bool read_count(size_t& offset, uint8_t low, uint64_t& count) const {
        if (low < 0x0f) {
            count = low;
            return true;
        }
        if (offset >= data_.size()) {
            return false;
        }
        const uint8_t marker = static_cast<uint8_t>(data_[offset++]);
        if ((marker >> 4) != 0x1) {
            return false;
        }
        const size_t bytes = size_t{1} << (marker & 0x0f);
        if (offset + bytes > data_.size()) {
            return false;
        }
        count = read_be(data_, offset, bytes);
        offset += bytes;
        return true;
    }

    bool parse_object(uint64_t object, Value& value, std::string& error, int depth) const {
        if (depth > 16) {
            error = "binary plist nesting too deep";
            return false;
        }

        const size_t start = object_offset(object);
        if (start == std::string::npos || start >= data_.size()) {
            error = "bad binary plist object reference";
            return false;
        }

        size_t offset = start + 1;
        const uint8_t marker = static_cast<uint8_t>(data_[start]);
        const uint8_t high = marker >> 4;
        const uint8_t low = marker & 0x0f;

        if (marker == 0x00) {
            value = {};
            return true;
        }
        if (marker == 0x08 || marker == 0x09) {
            value = {};
            value.type = Value::Type::Boolean;
            value.boolean = marker == 0x09;
            return true;
        }

        if (high == 0x1) {
            const size_t bytes = size_t{1} << low;
            if (offset + bytes > data_.size()) {
                error = "truncated binary plist integer";
                return false;
            }
            value = {};
            value.type = Value::Type::Integer;
            value.integer = read_be(data_, offset, bytes);
            return true;
        }

        if (high == 0x2) {
            const size_t bytes = size_t{1} << low;
            if (offset + bytes > data_.size() || (bytes != 4 && bytes != 8)) {
                error = "unsupported binary plist real";
                return false;
            }
            value = {};
            value.type = Value::Type::Real;
            if (bytes == 4) {
                const uint32_t raw = static_cast<uint32_t>(read_be(data_, offset, bytes));
                float f = 0.0f;
                std::memcpy(&f, &raw, sizeof(f));
                value.real = f;
            } else {
                const uint64_t raw = read_be(data_, offset, bytes);
                double d = 0.0;
                std::memcpy(&d, &raw, sizeof(d));
                value.real = d;
            }
            return true;
        }

        if (high == 0x4) {
            uint64_t count = 0;
            if (!read_count(offset, low, count) || offset + count > data_.size()) {
                error = "truncated binary plist data";
                return false;
            }
            value = {};
            value.type = Value::Type::Data;
            value.data.assign(reinterpret_cast<const uint8_t*>(data_.data() + offset),
                              reinterpret_cast<const uint8_t*>(data_.data() + offset + count));
            return true;
        }

        if (high == 0x5 || high == 0x6) {
            uint64_t count = 0;
            if (!read_count(offset, low, count)) {
                error = "bad binary plist string length";
                return false;
            }
            value = {};
            value.type = Value::Type::String;
            if (high == 0x5) {
                if (offset + count > data_.size()) {
                    error = "truncated binary plist string";
                    return false;
                }
                value.text = data_.substr(offset, static_cast<size_t>(count));
                return true;
            }
            if (offset + count * 2 > data_.size()) {
                error = "truncated binary plist utf16 string";
                return false;
            }
            value.text.reserve(static_cast<size_t>(count));
            for (uint64_t i = 0; i < count; ++i) {
                const auto ch = static_cast<char>(data_[offset + i * 2 + 1]);
                value.text.push_back(ch == '\0' ? '?' : ch);
            }
            return true;
        }

        if (high == 0xa) {
            uint64_t count = 0;
            if (!read_count(offset, low, count) ||
                count > 4096 ||
                offset + count * object_ref_size_ > data_.size()) {
                error = "bad binary plist array";
                return false;
            }
            value = {};
            value.type = Value::Type::Array;
            value.array.resize(static_cast<size_t>(count));
            for (uint64_t i = 0; i < count; ++i) {
                if (!parse_object(read_ref(offset + static_cast<size_t>(i) * object_ref_size_),
                                  value.array[static_cast<size_t>(i)],
                                  error,
                                  depth + 1)) {
                    return false;
                }
            }
            return true;
        }

        if (high == 0xd) {
            uint64_t count = 0;
            if (!read_count(offset, low, count) ||
                count > 4096 ||
                offset + count * object_ref_size_ * 2 > data_.size()) {
                error = "bad binary plist dictionary";
                return false;
            }
            value = {};
            value.type = Value::Type::Dictionary;
            const size_t keys = offset;
            const size_t vals = offset + static_cast<size_t>(count) * object_ref_size_;
            for (uint64_t i = 0; i < count; ++i) {
                Value key;
                if (!parse_object(read_ref(keys + static_cast<size_t>(i) * object_ref_size_),
                                  key,
                                  error,
                                  depth + 1)) {
                    return false;
                }
                if (key.type != Value::Type::String) {
                    error = "binary plist dictionary key is not a string";
                    return false;
                }
                Value child;
                if (!parse_object(read_ref(vals + static_cast<size_t>(i) * object_ref_size_),
                                  child,
                                  error,
                                  depth + 1)) {
                    return false;
                }
                value.dict.emplace(std::move(key.text), std::move(child));
            }
            return true;
        }

        error = "unsupported binary plist object marker";
        return false;
    }

    const std::string& data_;
    uint8_t offset_int_size_ = 0;
    uint8_t object_ref_size_ = 0;
    uint64_t top_object_ = 0;
    std::vector<size_t> offsets_;
};

} // namespace

const Value* Value::get(const std::string& key) const {
    if (type != Type::Dictionary) {
        return nullptr;
    }
    const auto it = dict.find(key);
    return it == dict.end() ? nullptr : &it->second;
}

Dictionary parse_loose_xml_dictionary(const std::string& xml) {
    Dictionary values;
    size_t pos = 0;
    while (true) {
        const size_t key_start = xml.find("<key>", pos);
        if (key_start == std::string::npos) {
            break;
        }
        const size_t key_end = xml.find("</key>", key_start);
        if (key_end == std::string::npos) {
            break;
        }
        const std::string key = xml.substr(key_start + 5, key_end - key_start - 5);
        const size_t value_start = xml.find('>', key_end + 6);
        if (value_start == std::string::npos) {
            break;
        }
        const size_t value_end = xml.find('<', value_start + 1);
        if (value_end == std::string::npos) {
            break;
        }
        values[utils::trim(key)] = utils::trim(xml.substr(value_start + 1, value_end - value_start - 1));
        pos = value_end;
    }
    return values;
}

std::string make_xml_dictionary(const Dictionary& values) {
    std::ostringstream out;
    out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    out << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ";
    out << "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    out << "<plist version=\"1.0\"><dict>\n";
    for (const auto& [key, value] : values) {
        out << "<key>" << key << "</key><string>" << value << "</string>\n";
    }
    out << "</dict></plist>\n";
    return out.str();
}

bool parse_binary_plist(const std::string& data, Value& root, std::string& error) {
    return BinaryPlistParser(data).parse(root, error);
}

std::string describe_binary_plist(const std::string& data) {
    return BinaryPlistDescriber(data).describe();
}

} // namespace airplayc::plist
