// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 matkhl. See LICENSE and THIRD_PARTY_NOTICES.md.
// FairPlay v3 FPLY parsing, modified-MD5 primitive, and unwrap orchestration.
#include "fairplay.h"
#include "fairplay_v3.h"

#include "../utils/string_utils.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <sstream>

namespace airplayc::crypto {
namespace {

uint32_t read_u32_be(const std::vector<uint8_t>& data, size_t offset) {
    return (static_cast<uint32_t>(data[offset]) << 24) |
           (static_cast<uint32_t>(data[offset + 1]) << 16) |
           (static_cast<uint32_t>(data[offset + 2]) << 8) |
           static_cast<uint32_t>(data[offset + 3]);
}

std::string size_status(size_t actual, size_t expected) {
    std::ostringstream out;
    out << actual << " bytes";
    if (actual != expected) {
        out << " (expected " << expected << ")";
    }
    return out.str();
}

uint32_t read_u32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

void write_u32_le(uint32_t value, uint8_t* out) {
    out[0] = static_cast<uint8_t>(value & 0xff);
    out[1] = static_cast<uint8_t>((value >> 8) & 0xff);
    out[2] = static_cast<uint8_t>((value >> 16) & 0xff);
    out[3] = static_cast<uint8_t>((value >> 24) & 0xff);
}

uint32_t rotl32(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32 - bits));
}

std::array<uint8_t, 16> fairplay_modified_md5(const uint8_t* data, size_t bytes, const std::array<uint8_t, 16>& key) {
    constexpr std::array<uint32_t, 64> kMd5Shift{
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

    std::array<uint8_t, 64> block{};
    const size_t copy_bytes = std::min<size_t>(block.size(), bytes);
    if (copy_bytes != 0 && data != nullptr) {
        std::copy(data, data + copy_bytes, block.begin());
    }

    const std::array<uint32_t, 4> initial{
        read_u32_le(key.data()),
        read_u32_le(key.data() + 4),
        read_u32_le(key.data() + 8),
        read_u32_le(key.data() + 12)};

    uint32_t a = initial[0];
    uint32_t b = initial[1];
    uint32_t c = initial[2];
    uint32_t d = initial[3];

    for (uint32_t i = 0; i < 64; ++i) {
        uint32_t j = 0;
        if (i <= 15) {
            j = i;
        } else if (i <= 31) {
            j = (5 * i + 1) % 16;
        } else if (i <= 47) {
            j = (3 * i + 5) % 16;
        } else {
            j = (7 * i) % 16;
        }

        const uint8_t* word = block.data() + (4 * j);
        const uint32_t input = (static_cast<uint32_t>(word[0]) << 24) |
                               (static_cast<uint32_t>(word[1]) << 16) |
                               (static_cast<uint32_t>(word[2]) << 8) |
                               static_cast<uint32_t>(word[3]);
        const auto sine_term = static_cast<uint32_t>(4294967296.0 * std::fabs(std::sin(static_cast<double>(i + 1))));
        uint32_t mixed = a + input + sine_term;
        if (i <= 15) {
            mixed += (b & c) | (~b & d);
        } else if (i <= 31) {
            mixed += (b & d) | (c & ~d);
        } else if (i <= 47) {
            mixed += b ^ c ^ d;
        } else {
            mixed += c ^ (b | ~d);
        }

        mixed = rotl32(mixed, kMd5Shift[i]) + b;
        const uint32_t old_d = d;
        d = c;
        c = b;
        b = mixed;
        a = old_d;

        if (i == 31) {
            std::array<uint32_t, 16> words{};
            for (size_t idx = 0; idx < words.size(); ++idx) {
                words[idx] = read_u32_le(block.data() + idx * 4);
            }
            std::swap(words[a & 15], words[b & 15]);
            std::swap(words[c & 15], words[d & 15]);
            std::swap(words[(a >> 4) & 15], words[(b >> 4) & 15]);
            std::swap(words[(a >> 8) & 15], words[(b >> 8) & 15]);
            std::swap(words[(a >> 12) & 15], words[(b >> 12) & 15]);
            for (size_t idx = 0; idx < words.size(); ++idx) {
                write_u32_le(words[idx], block.data() + idx * 4);
            }
        }
    }

    std::array<uint8_t, 16> out{};
    write_u32_le(initial[0] + a, out.data());
    write_u32_le(initial[1] + b, out.data() + 4);
    write_u32_le(initial[2] + c, out.data() + 8);
    write_u32_le(initial[3] + d, out.data() + 12);
    return out;
}

bool decode_exact_hex(const char* hex, std::vector<uint8_t>& out, size_t expected) {
    return utils::hex_decode(hex, out) && out.size() == expected;
}

std::vector<uint8_t> xor_16(const std::vector<uint8_t>& left, const std::vector<uint8_t>& right) {
    std::vector<uint8_t> out(16);
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(left[i] ^ right[i]);
    }
    return out;
}

bool derive_fairplay_tokenless_key(const FairPlayActiveUnwrapInput& input,
                                   std::vector<uint8_t>& tokenless_key,
                                   std::string& error) {
    tokenless_key.clear();
    if (derive_fairplay_tokenless_key_native(input, tokenless_key, error)) {
        return true;
    }
    if (error.empty()) {
        error = "FairPlay tokenless key derivation failed";
    }
    return false;
}

}

bool fairplay_self_test(std::string& error) {
    struct ModifiedMd5Case {
        std::array<uint8_t, 64> block;
        std::array<uint8_t, 16> key;
        const char* expected_hex;
    };

    ModifiedMd5Case zero_case{};
    zero_case.expected_hex = "971ccdf7813648a532d8682b39a60cf9";

    ModifiedMd5Case a_case{};
    a_case.block.fill(0x41);
    a_case.key.fill(0x41);
    a_case.expected_hex = "695b0c3715d9d4ceb4bfee317c92de79";

    std::vector<uint8_t> expected;
    const std::array<ModifiedMd5Case, 2> cases{zero_case, a_case};
    for (size_t i = 0; i < cases.size(); ++i) {
        const auto actual = fairplay_modified_md5(cases[i].block.data(), cases[i].block.size(), cases[i].key);
        if (!decode_exact_hex(cases[i].expected_hex, expected, actual.size()) ||
            !std::equal(actual.begin(), actual.end(), expected.begin())) {
            error = "FairPlay modified-MD5 vector " + std::to_string(i) + " failed";
            return false;
        }
    }

    std::array<uint8_t, 64> incremental_block{};
    std::array<uint8_t, 16> incremental_key{};
    for (size_t i = 0; i < incremental_block.size(); ++i) {
        incremental_block[i] = static_cast<uint8_t>(i);
    }
    for (size_t i = 0; i < incremental_key.size(); ++i) {
        incremental_key[i] = static_cast<uint8_t>(i + 64);
    }
    const auto incremental = fairplay_modified_md5(incremental_block.data(), incremental_block.size(), incremental_key);
    if (!decode_exact_hex("086862637e36ec8ccfeed2d71d459bf0", expected, incremental.size()) ||
        !std::equal(incremental.begin(), incremental.end(), expected.begin())) {
        error = "FairPlay modified-MD5 incremental vector failed";
        return false;
    }

    std::vector<uint8_t> real_block;
    std::vector<uint8_t> real_key;
    if (!decode_exact_hex("fa9cad4d4b68268c7ff38899de922e951eefbf616443ab486b700a3f743df20ddd71853546f2ef515d63e27a37c510de0971853546f2ef515d63e27a37c510de",
                          real_block,
                          64) ||
        !decode_exact_hex("dcdcf3b90b74dcfb867ff76016729051", real_key, 16)) {
        error = "FairPlay modified-MD5 real vector setup failed";
        return false;
    }
    std::array<uint8_t, 16> real_key_array{};
    std::copy(real_key.begin(), real_key.end(), real_key_array.begin());
    const auto real = fairplay_modified_md5(real_block.data(), real_block.size(), real_key_array);
    if (!decode_exact_hex("47da73bfb135d7aaf2934e953f6372ed", expected, real.size()) ||
        !std::equal(real.begin(), real.end(), expected.begin())) {
        error = "FairPlay modified-MD5 real vector failed";
        return false;
    }

    FairPlayContext active_context;
    active_context.key_message.resize(164);
    active_context.key_message[0] = 'F';
    active_context.key_message[1] = 'P';
    active_context.key_message[2] = 'L';
    active_context.key_message[3] = 'Y';
    active_context.key_message[4] = 0x03;
    active_context.key_message[5] = 0x01;
    active_context.key_message[6] = 0x03;
    active_context.key_message[7] = 0x00;
    active_context.key_message[8] = 0x00;
    active_context.key_message[9] = 0x00;
    active_context.key_message[10] = 0x00;
    active_context.key_message[11] = 0x98;
    active_context.key_message[12] = 0x02;
    active_context.key_message[13] = 0xaa;
    active_context.key_message[14] = 0xbb;
    active_context.key_message[15] = 0xcc;
    for (size_t i = 16; i < 144; ++i) {
        active_context.key_message[i] = static_cast<uint8_t>(i);
    }
    for (size_t i = 144; i < active_context.key_message.size(); ++i) {
        active_context.key_message[i] = static_cast<uint8_t>(0x80 + i);
    }

    active_context.ekey.resize(72);
    active_context.ekey[0] = 'F';
    active_context.ekey[1] = 'P';
    active_context.ekey[2] = 'L';
    active_context.ekey[3] = 'Y';
    active_context.ekey[4] = 0x01;
    active_context.ekey[5] = 0x02;
    active_context.ekey[6] = 0x01;
    active_context.ekey[7] = 0x00;
    active_context.ekey[8] = 0x00;
    active_context.ekey[9] = 0x00;
    active_context.ekey[10] = 0x00;
    active_context.ekey[11] = 0x3c;
    active_context.ekey[12] = 0x00;
    active_context.ekey[13] = 0x00;
    active_context.ekey[14] = 0x00;
    active_context.ekey[15] = 0x00;
    for (size_t i = 16; i < 32; ++i) {
        active_context.ekey[i] = static_cast<uint8_t>(0x10 + i);
    }
    active_context.ekey[32] = 0x00;
    active_context.ekey[33] = 0x00;
    active_context.ekey[34] = 0x00;
    active_context.ekey[35] = 0x10;
    for (size_t i = 36; i < 52; ++i) {
        active_context.ekey[i] = static_cast<uint8_t>(0x40 + i);
    }
    for (size_t i = 52; i < 72; ++i) {
        active_context.ekey[i] = static_cast<uint8_t>(0x70 + i);
    }

    const auto active = extract_fairplay_active_unwrap_input(active_context);
    if (!active.valid ||
        active.setup_mode != 0x02 ||
        active.key_message_core.size() != 128 ||
        active.ekey_token.size() != 16 ||
        active.ekey_tail_seed.size() != 16 ||
        active.key_message_core.front() != 0x10 ||
        active.key_message_core.back() != 0x8f ||
        active.ekey_token.front() != 0x20 ||
        active.ekey_token.back() != 0x2f ||
        active.ekey_tail_seed.front() != 0xa8 ||
        active.ekey_tail_seed.back() != 0xb7) {
        error = "FairPlay active unwrap input extraction vector failed";
        return false;
    }

    return true;
}

FairPlayEkeyEnvelope parse_fairplay_ekey(const std::vector<uint8_t>& ekey) {
    FairPlayEkeyEnvelope envelope;
    if (ekey.size() < 12) {
        envelope.error = "ekey too short";
        return envelope;
    }
    if (ekey[0] != 'F' || ekey[1] != 'P' || ekey[2] != 'L' || ekey[3] != 'Y') {
        envelope.error = "ekey does not start with FPLY";
        return envelope;
    }

    envelope.version_major = ekey[4];
    envelope.version_minor = ekey[5];
    envelope.message_type = ekey[6];
    envelope.flags = ekey[7];
    envelope.payload_size = read_u32_be(ekey, 8);
    if (ekey.size() != 12ull + envelope.payload_size) {
        envelope.error = "ekey payload size mismatch";
        return envelope;
    }
    if (envelope.payload_size < 40) {
        envelope.error = "ekey payload too short";
        return envelope;
    }

    envelope.reserved = read_u32_be(ekey, 12);
    envelope.token.assign(ekey.begin() + 16, ekey.begin() + 32);
    const uint32_t wrapped_key_size = read_u32_be(ekey, 32);
    if (wrapped_key_size > envelope.payload_size || 36ull + wrapped_key_size > ekey.size()) {
        envelope.error = "ekey wrapped key size is invalid";
        return envelope;
    }

    envelope.wrapped_key.assign(ekey.begin() + 36, ekey.begin() + 36 + wrapped_key_size);
    envelope.tail.assign(ekey.begin() + 36 + wrapped_key_size, ekey.end());
    envelope.valid = true;
    return envelope;
}

FairPlayKeyMessage parse_fairplay_key_message(const std::vector<uint8_t>& key_message) {
    FairPlayKeyMessage message;
    if (key_message.size() < 12) {
        message.error = "key message too short";
        return message;
    }
    if (key_message[0] != 'F' || key_message[1] != 'P' ||
        key_message[2] != 'L' || key_message[3] != 'Y') {
        message.error = "key message does not start with FPLY";
        return message;
    }

    message.version_major = key_message[4];
    message.version_minor = key_message[5];
    message.message_type = key_message[6];
    message.flags = key_message[7];
    message.payload_size = read_u32_be(key_message, 8);
    if (key_message.size() != 12ull + message.payload_size) {
        message.error = "key message payload size mismatch";
        return message;
    }
    if (message.payload_size == 0) {
        message.error = "key message payload is empty";
        return message;
    }

    message.setup_mode = key_message[12];
    message.body.assign(key_message.begin() + 12, key_message.end());
    if (message.body.size() >= 20) {
        message.reply_tail.assign(message.body.end() - 20, message.body.end());
    }
    message.valid = true;
    return message;
}

FairPlayActiveUnwrapInput extract_fairplay_active_unwrap_input(const FairPlayContext& context) {
    FairPlayActiveUnwrapInput input;
    const auto envelope = parse_fairplay_ekey(context.ekey);
    if (!envelope.valid) {
        input.error = envelope.error;
        return input;
    }
    const auto key_message = parse_fairplay_key_message(context.key_message);
    if (!key_message.valid) {
        input.error = key_message.error;
        return input;
    }
    if (context.key_message.size() != 164) {
        input.error = "FairPlay key message must be 164 bytes";
        return input;
    }
    if (envelope.token.size() != 16) {
        input.error = "FairPlay ekey token must be 16 bytes";
        return input;
    }
    if (envelope.tail.size() != 20) {
        input.error = "FairPlay ekey tail must be 20 bytes";
        return input;
    }

    input.setup_mode = key_message.setup_mode;
    input.ekey_token = envelope.token;
    input.ekey_tail_seed.assign(envelope.tail.begin() + 4, envelope.tail.end());
    input.key_message_core.assign(context.key_message.begin() + 16, context.key_message.begin() + 144);
    input.valid = true;
    return input;
}

bool fairplay_modified_md5_digest(const std::vector<uint8_t>& block,
                                  const std::vector<uint8_t>& key,
                                  std::vector<uint8_t>& digest,
                                  std::string& error) {
    digest.clear();
    if (key.size() != 16) {
        error = "FairPlay modified-MD5 key must be 16 bytes";
        return false;
    }
    if (block.size() > 64) {
        error = "FairPlay modified-MD5 block must be at most 64 bytes";
        return false;
    }

    std::array<uint8_t, 16> key_array{};
    std::copy(key.begin(), key.end(), key_array.begin());
    const auto out = fairplay_modified_md5(block.empty() ? nullptr : block.data(), block.size(), key_array);
    digest.assign(out.begin(), out.end());
    return true;
}

bool unwrap_fairplay_active_input(const FairPlayActiveUnwrapInput& input,
                                  std::vector<uint8_t>& aes_key,
                                  std::string& error) {
    aes_key.clear();
    if (!input.valid) {
        error = input.error.empty() ? "FairPlay active input is invalid" : input.error;
        return false;
    }
    if (input.setup_mode > 3) {
        error = "FairPlay setup mode is unsupported";
        return false;
    }
    if (input.key_message_core.size() != 128) {
        error = "FairPlay active key-message core must be 128 bytes";
        return false;
    }
    if (input.ekey_token.size() != 16) {
        error = "FairPlay active ekey token must be 16 bytes";
        return false;
    }
    if (input.ekey_tail_seed.size() != 16) {
        error = "FairPlay active ekey tail seed must be 16 bytes";
        return false;
    }

    std::vector<uint8_t> tokenless_key;
    if (!derive_fairplay_tokenless_key(input, tokenless_key, error)) {
        return false;
    }
    if (tokenless_key.size() != 16) {
        error = "FairPlay tokenless key derivation returned an invalid key size";
        return false;
    }

    aes_key = xor_16(tokenless_key, input.ekey_token);
    return true;
}

std::string describe_fairplay_context(const FairPlayContext& context) {
    const auto envelope = parse_fairplay_ekey(context.ekey);
    const auto key_message = parse_fairplay_key_message(context.key_message);
    const auto active_input = extract_fairplay_active_unwrap_input(context);
    std::ostringstream out;
    out << "FairPlay context et=" << context.encryption_type
        << " fpMode=" << context.setup_mode
        << " keyMsg=" << size_status(context.key_message.size(), 164)
        << " eiv=" << size_status(context.eiv.size(), 16)
        << " ekey=" << size_status(context.ekey.size(), 72);

    if (!envelope.valid) {
        out << "\nFPLY ekey: invalid: " << envelope.error;
    } else {
        out << "\nFPLY ekey version=" << static_cast<unsigned>(envelope.version_major)
            << "." << static_cast<unsigned>(envelope.version_minor)
            << " messageType=" << static_cast<unsigned>(envelope.message_type)
            << " flags=" << static_cast<unsigned>(envelope.flags)
            << " payload=" << envelope.payload_size
            << " reserved=" << envelope.reserved
            << " token=" << envelope.token.size() << " bytes"
            << " wrappedKey=" << envelope.wrapped_key.size() << " bytes"
            << " tail=" << envelope.tail.size() << " bytes"
            << " tokenHex=" << utils::hex_encode(envelope.token.data(), envelope.token.size())
            << " wrappedKeyHex=" << utils::hex_encode(envelope.wrapped_key.data(), envelope.wrapped_key.size())
            << " tailHead=" << utils::hex_encode(envelope.tail.data(), std::min<size_t>(envelope.tail.size(), 8));
    }

    if (!key_message.valid) {
        out << "\nFPLY key message: invalid: " << key_message.error;
        return out.str();
    }

    out << "\nFPLY key message version=" << static_cast<unsigned>(key_message.version_major)
        << "." << static_cast<unsigned>(key_message.version_minor)
        << " messageType=" << static_cast<unsigned>(key_message.message_type)
        << " flags=" << static_cast<unsigned>(key_message.flags)
        << " payload=" << key_message.payload_size
        << " body=" << key_message.body.size() << " bytes"
        << " setupModeByte=" << static_cast<unsigned>(key_message.setup_mode)
        << " replyTail=" << key_message.reply_tail.size() << " bytes";
    if (!key_message.reply_tail.empty()) {
        out << " replyTailHex=" << utils::hex_encode(key_message.reply_tail.data(), key_message.reply_tail.size());
    }
    if (active_input.valid) {
        out << "\nFairPlay active unwrap input mode=" << static_cast<unsigned>(active_input.setup_mode)
            << " keyMessageCore=" << active_input.key_message_core.size() << " bytes"
            << " ekeyToken=" << active_input.ekey_token.size() << " bytes"
            << " ekeyTailSeed=" << active_input.ekey_tail_seed.size() << " bytes";
    } else {
        out << "\nFairPlay active unwrap input: invalid: " << active_input.error;
    }
    return out.str();
}

bool unwrap_fairplay_key(const FairPlayContext& context,
                         std::vector<uint8_t>& aes_key,
                         std::string& error) {
    aes_key.clear();
    const auto envelope = parse_fairplay_ekey(context.ekey);
    if (!envelope.valid) {
        error = envelope.error;
        return false;
    }
    if (context.key_message.size() != 164) {
        error = "FairPlay key message must be 164 bytes";
        return false;
    }
    if (context.eiv.size() != 16) {
        error = "FairPlay eiv must be 16 bytes";
        return false;
    }
    const auto active_input = extract_fairplay_active_unwrap_input(context);
    if (!active_input.valid) {
        error = active_input.error;
        return false;
    }

    return unwrap_fairplay_active_input(active_input, aes_key, error);
}

}
