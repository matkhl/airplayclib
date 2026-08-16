// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 matkhl. See LICENSE and THIRD_PARTY_NOTICES.md.
// FairPlay v3 audio-key unwrap. This project is based in part on PlayFair;
// attribution and license details are recorded in THIRD_PARTY_NOTICES.md.
#include "fairplay_v3.h"
#include "fairplay.h"
#include "fairplay_tables.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace airplayc::crypto {
namespace {

// ---- little-endian 32-bit word IO (generic) --------------------------------
uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
void wr32(uint32_t v, uint8_t* p) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

// ---- byte primitives used by the garble routine -----------------------------
uint8_t lo8(int64_t v) { return static_cast<uint8_t>(v & 0xff); }
int64_t rotl8(int64_t v, int64_t c) { return lo8(((v << c) & 0xff) | ((v & 0xff) >> (8 - c))); }
int64_t rotl8w(int64_t v, int64_t c) { return (v << c) | (v >> (8 - c)); }
int64_t xror8(int64_t v, int64_t c) { return c == 0 ? 0 : (((v >> c) & 0xff) | ((v & 0xff) << (8 - c))); }
int64_t xrol8(int64_t v, int64_t c) { return c == 0 ? 0 : (((v << c) & 0xff) | ((v & 0xff) >> (8 - c))); }
int64_t xrol32(int64_t v, int64_t c) { return c == 0 ? 0 : ((v << c) ^ (v >> (8 - c))); }
int64_t imod(int64_t a, int64_t b) { int64_t r = a % b; if (r < 0) r += b < 0 ? -b : b; return r; }
int64_t idiv(int64_t a, int64_t b) { return a / b; }
size_t pyidx(int64_t i, size_t n) { if (i < 0) i += static_cast<int64_t>(n); return static_cast<size_t>(i); }
uint8_t bget(const std::vector<uint8_t>& v, int64_t i) { return v[pyidx(i, v.size())]; }
void bset(std::vector<uint8_t>& v, int64_t i, int64_t val) { v[pyidx(i, v.size())] = lo8(val); }

// ---- FairPlay permutation ---------------------------------------------------
#include "fairplay_garble.inc"  // void garble_block(vector<uint8_t>& x5)

// ---- XOR a 16-byte block with a fixed 16-byte key --------------------------
std::array<uint8_t, 16> xor16(const uint8_t* in, const std::array<uint8_t, 16>& key) {
    std::array<uint8_t, 16> out{};
    for (size_t i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(in[i] ^ key[i]);
    return out;
}

// ---- per-mode S-box / table accessors --------------------------------------
uint8_t msg_sbox(size_t idx, uint8_t v) { return fpdata::kTableS2[((97 * idx) % 144) * 256 + v]; }
uint8_t ks_sbox(size_t idx, uint8_t v) { return fpdata::kTableS1[((31 * idx) % 0x28) * 256 + v]; }
uint8_t p2_sbox(size_t idx, uint8_t v) { return fpdata::kTableS4[((71 * idx) % 144) * 256 + v]; }

// ---- shared 16-lane shuffle (InvShiftRows-style) -----------------------------
constexpr int kLaneSrc[16] = {0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};
constexpr int kPerm1Hi[16] = {0x0, 0x5, 0xa, 0xf, 0x4, 0x9, 0xe, 0x3, 0x8, 0xd, 0x2, 0x7, 0xc, 0x1, 0x6, 0xb};
template <class F>
std::array<uint8_t, 16> shuffle_lanes(const std::array<uint8_t, 16>& in, F f) {
    std::array<uint8_t, 16> out{};
    for (int d = 0; d < 16; ++d) out[d] = static_cast<uint8_t>(f(d, in[kLaneSrc[d]]));
    return out;
}

// ---- message body exposed by offset -----------------------------------------
uint8_t msg_src(const FairPlayActiveUnwrapInput& in, size_t off) {
    if (off == 12) return in.setup_mode;
    if (off >= 16 && off < 144) return in.key_message_core[off - 16];
    return 0;
}

// ---- message_decrypt: per-mode CBC-ish block decrypt → 128 bytes (spec §3) -
std::array<uint8_t, 128> message_decrypt(const FairPlayActiveUnwrapInput& in) {
    const size_t mode = in.setup_mode;
    std::array<uint8_t, 128> out{};
    for (size_t i = 0; i < 8; ++i) {
        std::array<uint8_t, 16> b{};
        for (size_t j = 0; j < 16; ++j) {
            const size_t off = (mode == 3 ? 0x80 - 0x10 * i : 0x10 * (i + 1)) + j;
            b[j] = msg_src(in, off);
        }
        for (size_t r = 0; r < 9; ++r) {
            const size_t base = 0x80 - 0x10 * r;
            b = shuffle_lanes(b, [&](int d, uint8_t v) {
                return static_cast<uint8_t>(msg_sbox(base + d, v) ^ fpdata::kMessageKey[mode][base + d]);
            });
            std::array<uint8_t, 16> mixed{};
            for (size_t g = 0; g < 16; g += 4) {
                const uint32_t w = fpdata::kTableS9[0x000 + b[g]] ^ fpdata::kTableS9[0x100 + b[g + 1]] ^
                                   fpdata::kTableS9[0x200 + b[g + 2]] ^ fpdata::kTableS9[0x300 + b[g + 3]];
                wr32(w, mixed.data() + g);
            }
            b = mixed;
        }
        b = shuffle_lanes(b, [&](int d, uint8_t v) {
            return fpdata::kTableS10[(static_cast<size_t>(d) << 8) + v];
        });
        if (mode == 3) {
            const size_t pos = 0x70 - 0x10 * i;
            const uint8_t* prev = (i < 7) ? &in.key_message_core[pos - 16] : fpdata::kMessageIv[mode].data();
            for (size_t j = 0; j < 16; ++j) out[pos + j] = static_cast<uint8_t>(b[j] ^ prev[j]);
        } else {
            const size_t pos = 0x10 * i;
            const uint8_t* prev = (i > 0) ? &in.key_message_core[pos - 16] : fpdata::kMessageIv[mode].data();
            for (size_t j = 0; j < 16; ++j) out[pos + j] = static_cast<uint8_t>(b[j] ^ prev[j]);
        }
    }
    return out;
}

// ---- sap_hash: fill, diffuse, garble, fold to 16 bytes -----------------------
std::array<uint8_t, 16> sap_hash(const uint8_t* block_in) {
    std::vector<uint8_t> b0(fpdata::kSapBuffer0.begin(), fpdata::kSapBuffer0.end());
    std::vector<uint8_t> b1(210, 0);
    std::vector<uint8_t> b2(fpdata::kSapBuffer2.begin(), fpdata::kSapBuffer2.end());
    std::vector<uint8_t> b3(132, 0);
    std::vector<uint8_t> b4(fpdata::kSapBuffer4.begin(), fpdata::kSapBuffer4.end());
    static constexpr size_t kPick[11] = {18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30};

    for (int64_t i = 0; i < 210; ++i) {
        const size_t base = static_cast<size_t>(i % 64) & ~static_cast<size_t>(3);
        b1[static_cast<size_t>(i)] = block_in[base + (3 - static_cast<size_t>(i % 4))];
    }
    for (int64_t i = 0; i < 840; ++i) {
        const uint8_t x = b1[static_cast<uint32_t>(i - 155) % 210];
        const uint8_t y = b1[static_cast<uint32_t>(i - 57) % 210];
        const uint8_t z = b1[static_cast<uint32_t>(i - 13) % 210];
        const uint8_t w = b1[static_cast<uint32_t>(i) % 210];
        b1[static_cast<size_t>(i % 210)] = lo8(rotl8(y, 5) + (rotl8(z, 3) ^ w) - rotl8(x, 7));
    }

    garble_block(b0, b1, b2, b3, b4);

    std::array<uint8_t, 16> k{};
    k.fill(0xe1);
    for (size_t i = 0; i < 11; ++i) k[i] = (i == 3) ? 0x3d : lo8(k[i] + b3[kPick[i] * 4]);
    for (size_t i = 0; i < b0.size(); ++i) k[i % 16] ^= b0[i];
    for (size_t i = 0; i < b2.size(); ++i) k[i % 16] ^= b2[i];
    for (size_t i = 0; i < b1.size(); ++i) k[i % 16] ^= b1[i];
    for (int64_t outer = 0; outer < 16; ++outer) {
        for (int64_t i = 0; i < 16; ++i) {
            const uint8_t x = k[static_cast<uint32_t>(i - 7) % 16];
            const uint8_t y = k[static_cast<size_t>(i % 16)];
            const uint8_t z = k[static_cast<uint32_t>(i - 37) % 16];
            const uint8_t w = k[static_cast<uint32_t>(i - 177) % 16];
            k[static_cast<size_t>(i)] = static_cast<uint8_t>(rotl8(x, 1) ^ y ^ rotl8(z, 6) ^ rotl8(w, 5));
        }
    }
    return k;
}

// ---- session_key: 5-round MD5/sap_hash mix to 16 bytes -----------------------
std::array<uint8_t, 16> session_key(const FairPlayActiveUnwrapInput& in) {
    const auto dm = message_decrypt(in);
    std::array<uint8_t, 320> sap{};
    size_t o = 0;
    std::copy(fpdata::kStaticSource1.begin(), fpdata::kStaticSource1.end(), sap.begin() + o);
    o += fpdata::kStaticSource1.size();
    std::copy(dm.begin(), dm.end(), sap.begin() + o);
    o += dm.size();
    std::copy(fpdata::kDefaultSap.begin() + 0x80, fpdata::kDefaultSap.begin() + 0x100, sap.begin() + o);
    o += 0x80;
    std::copy(fpdata::kStaticSource2.begin(), fpdata::kStaticSource2.end(), sap.begin() + o);

    std::vector<uint8_t> key(fpdata::kInitialSessionKey.begin(), fpdata::kInitialSessionKey.end());
    for (size_t round = 0; round < 5; ++round) {
        const uint8_t* base = sap.data() + round * 64;
        const std::vector<uint8_t> block(base, base + 64);
        std::vector<uint8_t> md5;
        std::string err;
        if (!fairplay_modified_md5_digest(block, key, md5, err)) return {};
        auto hash = sap_hash(base);
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t v = rd32(hash.data() + i * 4) + rd32(md5.data() + i * 4);
            wr32(v, hash.data() + i * 4);
        }
        key.assign(hash.begin(), hash.end());
    }

    std::array<uint8_t, 16> out{};
    std::copy(key.begin(), key.end(), out.begin());
    for (size_t i = 0; i < 16; i += 4) {
        std::swap(out[i], out[i + 3]);
        std::swap(out[i + 1], out[i + 2]);
    }
    for (auto& byte : out) byte ^= 0x79;
    return out;
}

// ---- key_schedule: AES-like expansion to 11x4 u32 ----------------------------
std::array<std::array<uint32_t, 4>, 11> key_schedule(const std::array<uint8_t, 16>& key_material) {
    auto buf = xor16(key_material.data(), fpdata::kTKey);
    std::array<std::array<uint32_t, 4>, 11> sched{};
    size_t ti = 0;
    for (size_t round = 0; round < 11; ++round) {
        sched[round][0] = rd32(buf.data());
        buf[0] ^= static_cast<uint8_t>(ks_sbox(ti + 0, buf[13]) ^ fpdata::kIndexMangle[round]);
        buf[1] ^= ks_sbox(ti + 1, buf[14]);
        buf[2] ^= ks_sbox(ti + 2, buf[15]);
        buf[3] ^= ks_sbox(ti + 3, buf[12]);
        ti += 4;
        uint32_t w0 = rd32(buf.data()), w1 = rd32(buf.data() + 4), w2 = rd32(buf.data() + 8), w3 = rd32(buf.data() + 12);
        sched[round][1] = w1; w1 ^= w0;
        sched[round][2] = w2; w2 ^= w1;
        sched[round][3] = w3; w3 ^= w2;
        wr32(w0, buf.data()); wr32(w1, buf.data() + 4); wr32(w2, buf.data() + 8); wr32(w3, buf.data() + 12);
    }
    return sched;
}

// ---- block_decrypt: AES-like inverse cipher ---------------------------------
std::array<uint8_t, 16> block_decrypt(std::array<uint8_t, 16> block,
                                      const std::array<std::array<uint32_t, 4>, 11>& sched) {
    for (size_t i = 0; i < 4; ++i) wr32(rd32(block.data() + i * 4) ^ sched[10][i], block.data() + i * 4);
    block = shuffle_lanes(block, [&](int d, uint8_t v) {
        return fpdata::kTableS3[(static_cast<size_t>(kPerm1Hi[d]) << 8) + v];
    });
    for (size_t round = 0; round < 9; ++round) {
        std::array<uint8_t, 16> key{};
        for (size_t i = 0; i < 4; ++i) wr32(sched[9 - round][i], key.data() + i * 4);
        std::array<uint32_t, 4> w{};
        w[0] = fpdata::kTableS5[(block[3] ^ key[3]) & 0xff] ^ fpdata::kTableS6[(block[2] ^ key[2]) & 0xff] ^
               fpdata::kTableS8[(block[0] ^ key[0]) & 0xff] ^ fpdata::kTableS7[(block[1] ^ key[1]) & 0xff];
        w[1] = fpdata::kTableS6[(block[6] ^ key[6]) & 0xff] ^ fpdata::kTableS5[(block[7] ^ key[7]) & 0xff] ^
               fpdata::kTableS8[(block[4] ^ key[4]) & 0xff] ^ fpdata::kTableS7[(block[5] ^ key[5]) & 0xff];
        w[2] = fpdata::kTableS5[(block[11] ^ key[11]) & 0xff] ^ fpdata::kTableS6[(block[10] ^ key[10]) & 0xff] ^
               fpdata::kTableS7[(block[9] ^ key[9]) & 0xff] ^ fpdata::kTableS8[(block[8] ^ key[8]) & 0xff];
        w[3] = fpdata::kTableS5[(block[15] ^ key[15]) & 0xff] ^ fpdata::kTableS6[(block[14] ^ key[14]) & 0xff] ^
               fpdata::kTableS7[(block[13] ^ key[13]) & 0xff] ^ fpdata::kTableS8[(block[12] ^ key[12]) & 0xff];
        for (size_t i = 0; i < 4; ++i) wr32(w[i], block.data() + i * 4);
        const size_t pr = 8 - round;
        block = shuffle_lanes(block, [&](int d, uint8_t v) { return p2_sbox(pr * 16 + d, v); });
    }
    for (size_t i = 0; i < 4; ++i) wr32(rd32(block.data() + i * 4) ^ sched[0][i], block.data() + i * 4);
    return block;
}

std::vector<uint8_t> run_backhalf(const std::array<uint8_t, 16>& sap_key, const uint8_t* tail_seed) {
    const auto sched = key_schedule(sap_key);
    const auto t = xor16(tail_seed, fpdata::kZKey);
    const auto c = block_decrypt(t, sched);
    const auto x = xor16(c.data(), fpdata::kXKey);
    const auto fin = xor16(x.data(), fpdata::kZKey);
    return std::vector<uint8_t>(fin.begin(), fin.end());
}

}  // namespace

bool derive_fairplay_tokenless_key_native(const FairPlayActiveUnwrapInput& input,
                                          std::vector<uint8_t>& tokenless_key,
                                          std::string& error) {
    tokenless_key.clear();
    if (!input.valid) {
        error = input.error.empty() ? "FairPlay active input is invalid" : input.error;
        return false;
    }
    if (input.setup_mode > 3 || input.key_message_core.size() != 128 || input.ekey_tail_seed.size() != 16) {
        error = "FairPlay native active input has invalid size or mode";
        return false;
    }
    const auto sap_key = session_key(input);
    tokenless_key = run_backhalf(sap_key, input.ekey_tail_seed.data());
    return true;
}

}  // namespace airplayc::crypto
