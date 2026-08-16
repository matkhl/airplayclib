#include "payload_crypto.h"

#include "../crypto/crypto.h"

#include <algorithm>
#include <utility>

namespace airplayc::audio {
namespace {

constexpr size_t kAirPlay2TrailerBytes = 24;
constexpr size_t kAirPlay2NonceBytes = 8;
constexpr size_t kAirPlay2TagBytes = 16;

void append_u32_be(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

bool payload_bounds(const rtp::CapturedPacket& packet,
                    size_t& ciphertext_offset,
                    size_t& ciphertext_bytes,
                    size_t& nonce_offset,
                    size_t& tag_offset,
                    std::string& error) {
    if (packet.payload_offset > packet.datagram.size()) {
        error = "RTP payload offset is past datagram end";
        return false;
    }

    const size_t payload_bytes = packet.datagram.size() - packet.payload_offset;
    if (payload_bytes < kAirPlay2TrailerBytes) {
        error = "RTP payload is too small for AirPlay2 nonce/tag trailer";
        return false;
    }

    ciphertext_offset = packet.payload_offset;
    ciphertext_bytes = payload_bytes - kAirPlay2TrailerBytes;
    nonce_offset = packet.datagram.size() - kAirPlay2TrailerBytes;
    tag_offset = packet.datagram.size() - kAirPlay2TagBytes;
    return true;
}

std::vector<uint8_t> aad_for_packet(const rtp::CapturedPacket& packet) {
    std::vector<uint8_t> aad;
    append_u32_be(aad, packet.info.timestamp);
    append_u32_be(aad, packet.info.ssrc);
    return aad;
}

std::vector<uint8_t> chacha_nonce_from_airplay_nonce(const uint8_t* nonce8) {
    std::vector<uint8_t> nonce12(12, 0);
    std::copy(nonce8, nonce8 + kAirPlay2NonceBytes, nonce12.begin() + 4);
    return nonce12;
}

} // namespace

bool decrypt_airplay2_payload(const rtp::CapturedPacket& packet,
                              const std::vector<uint8_t>& chacha_key,
                              DecryptedPayload& decrypted,
                              std::string& error) {
    decrypted = {};

    size_t ciphertext_offset = 0;
    size_t ciphertext_bytes = 0;
    size_t nonce_offset = 0;
    size_t tag_offset = 0;
    if (!payload_bounds(packet, ciphertext_offset, ciphertext_bytes, nonce_offset, tag_offset, error)) {
        return false;
    }

    const auto aad = aad_for_packet(packet);
    const auto nonce = chacha_nonce_from_airplay_nonce(packet.datagram.data() + nonce_offset);
    std::vector<uint8_t> tag(packet.datagram.begin() + tag_offset, packet.datagram.end());
    std::vector<uint8_t> plaintext;
    if (!crypto::chacha20_poly1305_decrypt(chacha_key,
                                           nonce,
                                           aad,
                                           packet.datagram.data() + ciphertext_offset,
                                           ciphertext_bytes,
                                           tag,
                                           plaintext,
                                           error)) {
        return false;
    }

    decrypted.sequence = packet.info.sequence;
    decrypted.timestamp = packet.info.timestamp;
    decrypted.ssrc = packet.info.ssrc;
    decrypted.plaintext = std::move(plaintext);
    return true;
}

bool decrypt_raop_aes_cbc_payload(const rtp::CapturedPacket& packet,
                                  const std::vector<uint8_t>& aes_key,
                                  const std::vector<uint8_t>& aes_iv,
                                  DecryptedPayload& decrypted,
                                  std::string& error) {
    decrypted = {};
    if (packet.payload_offset > packet.datagram.size()) {
        error = "RTP payload offset is past datagram end";
        return false;
    }

    const size_t payload_bytes = packet.datagram.size() - packet.payload_offset;
    const size_t encrypted_bytes = (payload_bytes / 16) * 16;
    if (encrypted_bytes == 0) {
        error = "RTP payload has no AES-CBC blocks";
        return false;
    }

    std::vector<uint8_t> plaintext;
    if (!crypto::aes_128_cbc_decrypt_no_padding(aes_key,
                                                aes_iv,
                                                packet.datagram.data() + packet.payload_offset,
                                                encrypted_bytes,
                                                plaintext,
                                                error)) {
        return false;
    }

    plaintext.insert(plaintext.end(),
                     packet.datagram.begin() + packet.payload_offset + encrypted_bytes,
                     packet.datagram.end());

    decrypted.sequence = packet.info.sequence;
    decrypted.timestamp = packet.info.timestamp;
    decrypted.ssrc = packet.info.ssrc;
    decrypted.plaintext = std::move(plaintext);
    return true;
}

} // namespace airplayc::audio
