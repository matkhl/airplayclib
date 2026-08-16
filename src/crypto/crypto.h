#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace airplayc::crypto {

std::vector<uint8_t> random_bytes(size_t count);
std::string random_hex(size_t bytes);

bool chacha20_poly1305_decrypt(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& nonce,
                               const std::vector<uint8_t>& aad,
                               const uint8_t* ciphertext,
                               size_t ciphertext_bytes,
                               const std::vector<uint8_t>& tag,
                               std::vector<uint8_t>& plaintext,
                               std::string& error);
bool aes_128_cbc_decrypt_no_padding(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv,
                                    const uint8_t* ciphertext,
                                    size_t ciphertext_bytes,
                                    std::vector<uint8_t>& plaintext,
                                    std::string& error);
bool aes_128_cbc_encrypt_no_padding(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv,
                                    const uint8_t* plaintext,
                                    size_t plaintext_bytes,
                                    std::vector<uint8_t>& ciphertext,
                                    std::string& error);
bool aes_128_ecb_decrypt_no_padding(const std::vector<uint8_t>& key,
                                    const uint8_t* ciphertext,
                                    size_t ciphertext_bytes,
                                    std::vector<uint8_t>& plaintext,
                                    std::string& error);
bool aes_128_ecb_encrypt_no_padding(const std::vector<uint8_t>& key,
                                    const uint8_t* plaintext,
                                    size_t plaintext_bytes,
                                    std::vector<uint8_t>& ciphertext,
                                    std::string& error);
bool sha1_digest(const uint8_t* data,
                 size_t data_bytes,
                 std::vector<uint8_t>& digest,
                 std::string& error);
bool sha256_digest(const uint8_t* data,
                   size_t data_bytes,
                   std::vector<uint8_t>& digest,
                   std::string& error);
bool sha512_digest(const uint8_t* data,
                   size_t data_bytes,
                   std::vector<uint8_t>& digest,
                   std::string& error);
bool hmac_sha1(const std::vector<uint8_t>& key,
               const uint8_t* data,
               size_t data_bytes,
               std::vector<uint8_t>& digest,
               std::string& error);
bool hmac_sha256(const std::vector<uint8_t>& key,
                 const uint8_t* data,
                 size_t data_bytes,
                 std::vector<uint8_t>& digest,
                 std::string& error);
bool hmac_sha512(const std::vector<uint8_t>& key,
                 const uint8_t* data,
                 size_t data_bytes,
                 std::vector<uint8_t>& digest,
                 std::string& error);
bool chacha20_poly1305_self_test(std::string& error);
bool aes_128_cbc_self_test(std::string& error);
bool aes_128_ecb_self_test(std::string& error);
bool hash_hmac_self_test(std::string& error);

} // namespace airplayc::crypto
