#include "crypto.h"

#include "../utils/string_utils.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <sstream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>

namespace airplayc::crypto {
namespace {

std::string ntstatus_hex(NTSTATUS status) {
    std::ostringstream out;
    out << "0x" << std::hex << static_cast<unsigned long>(status);
    return out.str();
}

void close_alg(BCRYPT_ALG_HANDLE handle) {
    if (handle) {
        BCryptCloseAlgorithmProvider(handle, 0);
    }
}

void destroy_key(BCRYPT_KEY_HANDLE handle) {
    if (handle) {
        BCryptDestroyKey(handle);
    }
}

bool aes_128_no_padding(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>* iv,
                        const uint8_t* input,
                        size_t input_bytes,
                        bool encrypt,
                        std::vector<uint8_t>& output,
                        std::string& error) {
    output.clear();
    if (key.size() != 16) {
        error = "AES-128 key must be 16 bytes";
        return false;
    }
    if (iv && iv->size() != 16) {
        error = "AES-128-CBC IV must be 16 bytes";
        return false;
    }
    if (input_bytes % 16 != 0) {
        error = "AES input must be block aligned";
        return false;
    }
    if (input_bytes != 0 && input == nullptr) {
        error = "AES input pointer is null";
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) {
        error = "BCryptOpenAlgorithmProvider(AES) failed: " + ntstatus_hex(status);
        return false;
    }

    const wchar_t* chain_mode = iv ? BCRYPT_CHAIN_MODE_CBC : BCRYPT_CHAIN_MODE_ECB;
    status = BCryptSetProperty(alg,
                               BCRYPT_CHAINING_MODE,
                               reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(chain_mode)),
                               static_cast<ULONG>((wcslen(chain_mode) + 1) * sizeof(wchar_t)),
                               0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptSetProperty(AES chain mode) failed: " + ntstatus_hex(status);
        return false;
    }

    DWORD key_object_bytes = 0;
    DWORD property_bytes = 0;
    status = BCryptGetProperty(alg,
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_bytes),
                               sizeof(key_object_bytes),
                               &property_bytes,
                               0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " + ntstatus_hex(status);
        return false;
    }

    std::vector<uint8_t> key_object(key_object_bytes);
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptGenerateSymmetricKey(alg,
                                        &key_handle,
                                        key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(key.data()),
                                        static_cast<ULONG>(key.size()),
                                        0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptGenerateSymmetricKey(AES) failed: " + ntstatus_hex(status);
        return false;
    }

    std::vector<uint8_t> mutable_iv = iv ? *iv : std::vector<uint8_t>{};
    output.assign(input_bytes, 0);
    ULONG output_bytes = 0;
    if (encrypt) {
        status = BCryptEncrypt(key_handle,
                               const_cast<PUCHAR>(input),
                               static_cast<ULONG>(input_bytes),
                               nullptr,
                               mutable_iv.empty() ? nullptr : mutable_iv.data(),
                               static_cast<ULONG>(mutable_iv.size()),
                               output.empty() ? nullptr : output.data(),
                               static_cast<ULONG>(output.size()),
                               &output_bytes,
                               0);
    } else {
        status = BCryptDecrypt(key_handle,
                               const_cast<PUCHAR>(input),
                               static_cast<ULONG>(input_bytes),
                               nullptr,
                               mutable_iv.empty() ? nullptr : mutable_iv.data(),
                               static_cast<ULONG>(mutable_iv.size()),
                               output.empty() ? nullptr : output.data(),
                               static_cast<ULONG>(output.size()),
                               &output_bytes,
                               0);
    }

    destroy_key(key_handle);
    close_alg(alg);

    if (status < 0) {
        output.clear();
        error = std::string(encrypt ? "BCryptEncrypt(AES) failed: " : "BCryptDecrypt(AES) failed: ") +
                ntstatus_hex(status);
        return false;
    }

    output.resize(output_bytes);
    return true;
}

bool digest_bytes(const wchar_t* algorithm,
                  const std::vector<uint8_t>* key,
                  const uint8_t* data,
                  size_t data_bytes,
                  std::vector<uint8_t>& digest,
                  std::string& error) {
    digest.clear();
    if (data_bytes != 0 && data == nullptr) {
        error = "digest input pointer is null";
        return false;
    }
    if (key && key->empty()) {
        error = "HMAC key must not be empty";
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    const ULONG flags = key ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, algorithm, nullptr, flags);
    if (status < 0) {
        error = "BCryptOpenAlgorithmProvider(hash) failed: " + ntstatus_hex(status);
        return false;
    }

    DWORD object_bytes = 0;
    DWORD property_bytes = 0;
    status = BCryptGetProperty(alg,
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&object_bytes),
                               sizeof(object_bytes),
                               &property_bytes,
                               0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptGetProperty(hash object length) failed: " + ntstatus_hex(status);
        return false;
    }

    DWORD digest_bytes_count = 0;
    status = BCryptGetProperty(alg,
                               BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&digest_bytes_count),
                               sizeof(digest_bytes_count),
                               &property_bytes,
                               0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptGetProperty(hash length) failed: " + ntstatus_hex(status);
        return false;
    }

    std::vector<uint8_t> object(object_bytes);
    BCRYPT_HASH_HANDLE hash = nullptr;
    PUCHAR secret = key ? const_cast<PUCHAR>(key->data()) : nullptr;
    const ULONG secret_bytes = key ? static_cast<ULONG>(key->size()) : 0;
    status = BCryptCreateHash(alg,
                              &hash,
                              object.data(),
                              static_cast<ULONG>(object.size()),
                              secret,
                              secret_bytes,
                              0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptCreateHash failed: " + ntstatus_hex(status);
        return false;
    }

    status = BCryptHashData(hash,
                            const_cast<PUCHAR>(data),
                            static_cast<ULONG>(data_bytes),
                            0);
    if (status >= 0) {
        digest.assign(digest_bytes_count, 0);
        status = BCryptFinishHash(hash,
                                  digest.data(),
                                  static_cast<ULONG>(digest.size()),
                                  0);
    }

    BCryptDestroyHash(hash);
    close_alg(alg);

    if (status < 0) {
        digest.clear();
        error = "BCrypt hash operation failed: " + ntstatus_hex(status);
        return false;
    }

    return true;
}

bool digest_matches_hex(const std::vector<uint8_t>& actual, const char* expected_hex) {
    std::vector<uint8_t> expected;
    return utils::hex_decode(expected_hex, expected) && actual == expected;
}

} // namespace

std::vector<uint8_t> random_bytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    if (!bytes.empty()) {
        if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            bytes.assign(count, 0);
        }
    }
    return bytes;
}

std::string random_hex(size_t bytes) {
    auto data = random_bytes(bytes);
    return utils::hex_encode(data.data(), data.size());
}

bool chacha20_poly1305_decrypt(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& nonce,
                               const std::vector<uint8_t>& aad,
                               const uint8_t* ciphertext,
                               size_t ciphertext_bytes,
                               const std::vector<uint8_t>& tag,
                               std::vector<uint8_t>& plaintext,
                               std::string& error) {
    plaintext.clear();
    if (key.size() != 32) {
        error = "ChaCha20-Poly1305 key must be 32 bytes";
        return false;
    }
    if (nonce.size() != 12) {
        error = "ChaCha20-Poly1305 nonce must be 12 bytes";
        return false;
    }
    if (tag.size() != 16) {
        error = "ChaCha20-Poly1305 tag must be 16 bytes";
        return false;
    }
    if (ciphertext_bytes != 0 && ciphertext == nullptr) {
        error = "ciphertext pointer is null";
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_CHACHA20_POLY1305_ALGORITHM, nullptr, 0);
    if (status < 0) {
        error = "BCryptOpenAlgorithmProvider(CHACHA20_POLY1305) failed: " + ntstatus_hex(status);
        return false;
    }

    DWORD key_object_bytes = 0;
    DWORD property_bytes = 0;
    status = BCryptGetProperty(alg,
                               BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&key_object_bytes),
                               sizeof(key_object_bytes),
                               &property_bytes,
                               0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed: " + ntstatus_hex(status);
        return false;
    }

    std::vector<uint8_t> key_object(key_object_bytes);
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    status = BCryptGenerateSymmetricKey(alg,
                                        &key_handle,
                                        key_object.data(),
                                        static_cast<ULONG>(key_object.size()),
                                        const_cast<PUCHAR>(key.data()),
                                        static_cast<ULONG>(key.size()),
                                        0);
    if (status < 0) {
        close_alg(alg);
        error = "BCryptGenerateSymmetricKey failed: " + ntstatus_hex(status);
        return false;
    }

    plaintext.assign(ciphertext_bytes, 0);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = const_cast<PUCHAR>(nonce.data());
    auth_info.cbNonce = static_cast<ULONG>(nonce.size());
    auth_info.pbAuthData = aad.empty() ? nullptr : const_cast<PUCHAR>(aad.data());
    auth_info.cbAuthData = static_cast<ULONG>(aad.size());
    auth_info.pbTag = const_cast<PUCHAR>(tag.data());
    auth_info.cbTag = static_cast<ULONG>(tag.size());

    ULONG plaintext_bytes = 0;
    status = BCryptDecrypt(key_handle,
                           const_cast<PUCHAR>(ciphertext),
                           static_cast<ULONG>(ciphertext_bytes),
                           &auth_info,
                           nullptr,
                           0,
                           plaintext.empty() ? nullptr : plaintext.data(),
                           static_cast<ULONG>(plaintext.size()),
                           &plaintext_bytes,
                           0);

    destroy_key(key_handle);
    close_alg(alg);

    if (status < 0) {
        plaintext.clear();
        error = "BCryptDecrypt(CHACHA20_POLY1305) failed: " + ntstatus_hex(status);
        return false;
    }

    plaintext.resize(plaintext_bytes);
    return true;
}

bool aes_128_cbc_decrypt_no_padding(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv,
                                    const uint8_t* ciphertext,
                                    size_t ciphertext_bytes,
                                    std::vector<uint8_t>& plaintext,
                                    std::string& error) {
    return aes_128_no_padding(key, &iv, ciphertext, ciphertext_bytes, false, plaintext, error);
}

bool aes_128_cbc_encrypt_no_padding(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& iv,
                                    const uint8_t* plaintext,
                                    size_t plaintext_bytes,
                                    std::vector<uint8_t>& ciphertext,
                                    std::string& error) {
    return aes_128_no_padding(key, &iv, plaintext, plaintext_bytes, true, ciphertext, error);
}

bool aes_128_ecb_decrypt_no_padding(const std::vector<uint8_t>& key,
                                    const uint8_t* ciphertext,
                                    size_t ciphertext_bytes,
                                    std::vector<uint8_t>& plaintext,
                                    std::string& error) {
    return aes_128_no_padding(key, nullptr, ciphertext, ciphertext_bytes, false, plaintext, error);
}

bool aes_128_ecb_encrypt_no_padding(const std::vector<uint8_t>& key,
                                    const uint8_t* plaintext,
                                    size_t plaintext_bytes,
                                    std::vector<uint8_t>& ciphertext,
                                    std::string& error) {
    return aes_128_no_padding(key, nullptr, plaintext, plaintext_bytes, true, ciphertext, error);
}

bool sha1_digest(const uint8_t* data,
                 size_t data_bytes,
                 std::vector<uint8_t>& digest,
                 std::string& error) {
    return digest_bytes(BCRYPT_SHA1_ALGORITHM, nullptr, data, data_bytes, digest, error);
}

bool sha256_digest(const uint8_t* data,
                   size_t data_bytes,
                   std::vector<uint8_t>& digest,
                   std::string& error) {
    return digest_bytes(BCRYPT_SHA256_ALGORITHM, nullptr, data, data_bytes, digest, error);
}

bool sha512_digest(const uint8_t* data,
                   size_t data_bytes,
                   std::vector<uint8_t>& digest,
                   std::string& error) {
    return digest_bytes(BCRYPT_SHA512_ALGORITHM, nullptr, data, data_bytes, digest, error);
}

bool hmac_sha1(const std::vector<uint8_t>& key,
               const uint8_t* data,
               size_t data_bytes,
               std::vector<uint8_t>& digest,
               std::string& error) {
    return digest_bytes(BCRYPT_SHA1_ALGORITHM, &key, data, data_bytes, digest, error);
}

bool hmac_sha256(const std::vector<uint8_t>& key,
                 const uint8_t* data,
                 size_t data_bytes,
                 std::vector<uint8_t>& digest,
                 std::string& error) {
    return digest_bytes(BCRYPT_SHA256_ALGORITHM, &key, data, data_bytes, digest, error);
}

bool hmac_sha512(const std::vector<uint8_t>& key,
                 const uint8_t* data,
                 size_t data_bytes,
                 std::vector<uint8_t>& digest,
                 std::string& error) {
    return digest_bytes(BCRYPT_SHA512_ALGORITHM, &key, data, data_bytes, digest, error);
}

bool chacha20_poly1305_self_test(std::string& error) {
    std::vector<uint8_t> key;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> aad;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> expected_plaintext;

    utils::hex_decode("808182838485868788898a8b8c8d8e8f"
                      "909192939495969798999a9b9c9d9e9f", key);
    utils::hex_decode("070000004041424344454647", nonce);
    utils::hex_decode("50515253c0c1c2c3c4c5c6c7", aad);
    utils::hex_decode("d31a8d34648e60db7b86afbc53ef7ec2"
                      "a4aded51296e08fea9e2b5a736ee62d"
                      "63dbea45e8ca9671282fafb69da92728b"
                      "1a71de0a9e060b2905d6a5b67ecd3b369"
                      "2ddbd7f2d778b8c9803aee328091b58fab"
                      "324e4fad675945585808b4831d7bc3ff4"
                      "def08e4b7a9de576d26586cec64b6116", ciphertext);
    utils::hex_decode("1ae10b594f09e26a7e902ecbd0600691", tag);
    utils::hex_decode("4c616469657320616e642047656e746c"
                      "656d656e206f662074686520636c617373"
                      "206f66202739393a204966204920636f75"
                      "6c64206f6666657220796f75206f6e6c79"
                      "206f6e652074697020666f722074686520"
                      "6675747572652c2073756e73637265656e"
                      "20776f756c642062652069742e", expected_plaintext);

    std::vector<uint8_t> plaintext;
    if (!chacha20_poly1305_decrypt(key,
                                   nonce,
                                   aad,
                                   ciphertext.data(),
                                   ciphertext.size(),
                                   tag,
                                   plaintext,
                                   error)) {
        return false;
    }

    if (plaintext != expected_plaintext) {
        error = "RFC 8439 ChaCha20-Poly1305 plaintext mismatch";
        return false;
    }

    return true;
}

bool aes_128_cbc_self_test(std::string& error) {
    std::vector<uint8_t> key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> expected_plaintext;

    utils::hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key);
    utils::hex_decode("000102030405060708090a0b0c0d0e0f", iv);
    utils::hex_decode("7649abac8119b246cee98e9b12e9197d"
                      "5086cb9b507219ee95db113a917678b2"
                      "73bed6b8e3c1743b7116e69e22229516"
                      "3ff1caa1681fac09120eca307586e1a7", ciphertext);
    utils::hex_decode("6bc1bee22e409f96e93d7e117393172a"
                      "ae2d8a571e03ac9c9eb76fac45af8e51"
                      "30c81c46a35ce411e5fbc1191a0a52ef"
                      "f69f2445df4f9b17ad2b417be66c3710", expected_plaintext);

    std::vector<uint8_t> plaintext;
    if (!aes_128_cbc_decrypt_no_padding(key,
                                        iv,
                                        ciphertext.data(),
                                        ciphertext.size(),
                                        plaintext,
                                        error)) {
        return false;
    }

    if (plaintext != expected_plaintext) {
        error = "NIST AES-128-CBC plaintext mismatch";
        return false;
    }

    std::vector<uint8_t> encrypted;
    if (!aes_128_cbc_encrypt_no_padding(key,
                                        iv,
                                        expected_plaintext.data(),
                                        expected_plaintext.size(),
                                        encrypted,
                                        error)) {
        return false;
    }
    if (encrypted != ciphertext) {
        error = "NIST AES-128-CBC ciphertext mismatch";
        return false;
    }

    return true;
}

bool aes_128_ecb_self_test(std::string& error) {
    std::vector<uint8_t> key;
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;

    utils::hex_decode("2b7e151628aed2a6abf7158809cf4f3c", key);
    utils::hex_decode("6bc1bee22e409f96e93d7e117393172a", plaintext);
    utils::hex_decode("3ad77bb40d7a3660a89ecaf32466ef97", ciphertext);

    std::vector<uint8_t> encrypted;
    if (!aes_128_ecb_encrypt_no_padding(key,
                                        plaintext.data(),
                                        plaintext.size(),
                                        encrypted,
                                        error)) {
        return false;
    }
    if (encrypted != ciphertext) {
        error = "NIST AES-128-ECB ciphertext mismatch";
        return false;
    }

    std::vector<uint8_t> decrypted;
    if (!aes_128_ecb_decrypt_no_padding(key,
                                        ciphertext.data(),
                                        ciphertext.size(),
                                        decrypted,
                                        error)) {
        return false;
    }
    if (decrypted != plaintext) {
        error = "NIST AES-128-ECB plaintext mismatch";
        return false;
    }

    return true;
}

bool hash_hmac_self_test(std::string& error) {
    const auto* abc = reinterpret_cast<const uint8_t*>("abc");
    const size_t abc_len = std::strlen("abc");

    std::vector<uint8_t> digest;
    if (!sha1_digest(abc, abc_len, digest, error) ||
        !digest_matches_hex(digest, "a9993e364706816aba3e25717850c26c9cd0d89d")) {
        error = error.empty() ? "SHA-1 known-answer vector failed" : error;
        return false;
    }
    if (!sha256_digest(abc, abc_len, digest, error) ||
        !digest_matches_hex(digest, "ba7816bf8f01cfea414140de5dae2223"
                                    "b00361a396177a9cb410ff61f20015ad")) {
        error = error.empty() ? "SHA-256 known-answer vector failed" : error;
        return false;
    }
    if (!sha512_digest(abc, abc_len, digest, error) ||
        !digest_matches_hex(digest, "ddaf35a193617abacc417349ae204131"
                                    "12e6fa4e89a97ea20a9eeee64b55d39a"
                                    "2192992a274fc1a836ba3c23a3feebbd"
                                    "454d4423643ce80e2a9ac94fa54ca49f")) {
        error = error.empty() ? "SHA-512 known-answer vector failed" : error;
        return false;
    }

    const std::vector<uint8_t> key{'k', 'e', 'y'};
    const char* quick = "The quick brown fox jumps over the lazy dog";
    const auto* quick_bytes = reinterpret_cast<const uint8_t*>(quick);
    const size_t quick_len = std::strlen(quick);
    if (!hmac_sha1(key, quick_bytes, quick_len, digest, error) ||
        !digest_matches_hex(digest, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9")) {
        error = error.empty() ? "HMAC-SHA1 known-answer vector failed" : error;
        return false;
    }
    if (!hmac_sha256(key, quick_bytes, quick_len, digest, error) ||
        !digest_matches_hex(digest, "f7bc83f430538424b13298e6aa6fb143"
                                    "ef4d59a14946175997479dbc2d1a3cd8")) {
        error = error.empty() ? "HMAC-SHA256 known-answer vector failed" : error;
        return false;
    }
    if (!hmac_sha512(key, quick_bytes, quick_len, digest, error) ||
        !digest_matches_hex(digest, "b42af09057bac1e2d41708e48a902e09"
                                    "b5ff7f12ab428a4fe86653c73dd248fb"
                                    "82f948a549f7b791a5b41915ee4d1ec3"
                                    "935357e4e2317250d0372afa2ebeeb3a")) {
        error = error.empty() ? "HMAC-SHA512 known-answer vector failed" : error;
        return false;
    }

    return true;
}

} // namespace airplayc::crypto
