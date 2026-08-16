#include "alac_decoder.h"

#include "../../deps/alac/ALACBitUtilities.h"
#include "../../deps/alac/ALACDecoder.h"
#include "../../deps/alac/aglib.h"

#include <algorithm>
#include <cstring>
#include <string>

namespace airplayc::audio {
namespace {

void append_u16_be(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

void append_u32_be(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

std::vector<uint8_t> make_magic_cookie(const AlacDecoderConfig& config) {
    std::vector<uint8_t> cookie;
    cookie.reserve(24);
    append_u32_be(cookie, config.samples_per_frame);
    cookie.push_back(0); // compatibleVersion
    cookie.push_back(static_cast<uint8_t>(config.bits_per_sample));
    cookie.push_back(PB0);
    cookie.push_back(MB0);
    cookie.push_back(KB0);
    cookie.push_back(static_cast<uint8_t>(config.channels));
    append_u16_be(cookie, MAX_RUN_DEFAULT);
    append_u32_be(cookie, 0); // maxFrameBytes, not required for decode
    append_u32_be(cookie, 0); // avgBitRate, not required for decode
    append_u32_be(cookie, config.sample_rate);
    return cookie;
}

} // namespace

struct AlacDecoder::Impl {
    std::unique_ptr<::ALACDecoder> decoder;
    AlacDecoderConfig config;
    bool configured = false;
};

AlacDecoder::AlacDecoder()
    : impl_(std::make_unique<Impl>()) {}

AlacDecoder::~AlacDecoder() = default;

bool AlacDecoder::configure(const AlacDecoderConfig& config, std::string& error) {
    if (config.channels == 0 || config.channels > 2) {
        error = "ALAC decoder currently supports mono/stereo AirPlay streams";
        return false;
    }
    if (config.bits_per_sample != 16) {
        error = "ALAC decoder currently supports 16-bit output only";
        return false;
    }
    if (config.samples_per_frame == 0) {
        error = "ALAC decoder samples_per_frame must be non-zero";
        return false;
    }

    auto decoder = std::make_unique<::ALACDecoder>();
    auto cookie = make_magic_cookie(config);
    const int32_t status = decoder->Init(cookie.data(), static_cast<uint32_t>(cookie.size()));
    if (status != ALAC_noErr) {
        error = "ALAC decoder Init failed with status " + std::to_string(status);
        return false;
    }

    impl_->decoder = std::move(decoder);
    impl_->config = config;
    impl_->configured = true;
    return true;
}

bool AlacDecoder::decode_frame(const uint8_t* data,
                               size_t bytes,
                               std::vector<int16_t>& pcm,
                               size_t& frame_count,
                               std::string& error) {
    pcm.clear();
    frame_count = 0;
    if (!impl_->configured) {
        error = "ALAC decoder is not configured";
        return false;
    }
    if (!data || bytes == 0) {
        error = "ALAC frame is empty";
        return false;
    }
    if (bytes > UINT32_MAX) {
        error = "ALAC frame is too large";
        return false;
    }

    std::vector<uint8_t> input(data, data + bytes);
    BitBuffer bits{};
    BitBufferInit(&bits, input.data(), static_cast<uint32_t>(input.size()));

    const size_t output_samples = static_cast<size_t>(impl_->config.samples_per_frame) * impl_->config.channels;
    std::vector<uint8_t> output(output_samples * sizeof(int16_t));
    uint32_t decoded_frames = 0;
    const int32_t status = impl_->decoder->Decode(&bits,
                                                  output.data(),
                                                  impl_->config.samples_per_frame,
                                                  impl_->config.channels,
                                                  &decoded_frames);
    if (status != ALAC_noErr) {
        error = "ALAC decoder Decode failed with status " + std::to_string(status);
        return false;
    }
    if (decoded_frames == 0 || decoded_frames > impl_->config.samples_per_frame) {
        error = "ALAC decoder returned invalid frame count";
        return false;
    }

    pcm.resize(static_cast<size_t>(decoded_frames) * impl_->config.channels);
    std::memcpy(pcm.data(), output.data(), pcm.size() * sizeof(int16_t));
    frame_count = decoded_frames;
    return true;
}

AudioFormat AlacDecoder::output_format() const {
    AudioFormat format;
    if (impl_->configured) {
        format.sample_rate = impl_->config.sample_rate;
        format.channels = impl_->config.channels;
        format.bits_per_sample = impl_->config.bits_per_sample;
    }
    return format;
}

} // namespace airplayc::audio
