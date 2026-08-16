#pragma once

#include "../rtp/rtp_receiver.h"

#include <cstdint>
#include <string>
#include <vector>

namespace airplayc::audio {

struct DecryptedPayload {
    uint16_t sequence = 0;
    uint32_t timestamp = 0;
    uint32_t ssrc = 0;
    std::vector<uint8_t> plaintext;
};

bool decrypt_airplay2_payload(const rtp::CapturedPacket& packet,
                              const std::vector<uint8_t>& chacha_key,
                              DecryptedPayload& decrypted,
                              std::string& error);
bool decrypt_raop_aes_cbc_payload(const rtp::CapturedPacket& packet,
                                  const std::vector<uint8_t>& aes_key,
                                  const std::vector<uint8_t>& aes_iv,
                                  DecryptedPayload& decrypted,
                                  std::string& error);

} // namespace airplayc::audio
