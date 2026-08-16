// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 matkhl. See LICENSE and THIRD_PARTY_NOTICES.md.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace airplayc::crypto {

struct FairPlayEkeyEnvelope {
    bool valid = false;
    uint8_t version_major = 0;
    uint8_t version_minor = 0;
    uint8_t message_type = 0;
    uint8_t flags = 0;
    uint32_t payload_size = 0;
    uint32_t reserved = 0;
    std::vector<uint8_t> token;
    std::vector<uint8_t> wrapped_key;
    std::vector<uint8_t> tail;
    std::string error;
};

struct FairPlayKeyMessage {
    bool valid = false;
    uint8_t version_major = 0;
    uint8_t version_minor = 0;
    uint8_t message_type = 0;
    uint8_t flags = 0;
    uint8_t setup_mode = 0;
    uint32_t payload_size = 0;
    std::vector<uint8_t> body;
    std::vector<uint8_t> reply_tail;
    std::string error;
};

struct FairPlayContext {
    uint64_t encryption_type = 0;
    uint64_t setup_mode = 0;
    std::vector<uint8_t> key_message;
    std::vector<uint8_t> ekey;
    std::vector<uint8_t> eiv;
};

struct FairPlayActiveUnwrapInput {
    bool valid = false;
    uint8_t setup_mode = 0;
    std::vector<uint8_t> key_message_core;
    std::vector<uint8_t> ekey_token;
    std::vector<uint8_t> ekey_tail_seed;
    std::string error;
};

FairPlayEkeyEnvelope parse_fairplay_ekey(const std::vector<uint8_t>& ekey);
FairPlayKeyMessage parse_fairplay_key_message(const std::vector<uint8_t>& key_message);
FairPlayActiveUnwrapInput extract_fairplay_active_unwrap_input(const FairPlayContext& context);
std::string describe_fairplay_context(const FairPlayContext& context);
bool fairplay_modified_md5_digest(const std::vector<uint8_t>& block,
                                  const std::vector<uint8_t>& key,
                                  std::vector<uint8_t>& digest,
                                  std::string& error);
bool fairplay_self_test(std::string& error);
bool unwrap_fairplay_active_input(const FairPlayActiveUnwrapInput& input,
                                  std::vector<uint8_t>& aes_key,
                                  std::string& error);
bool unwrap_fairplay_key(const FairPlayContext& context,
                         std::vector<uint8_t>& aes_key,
                         std::string& error);

}
