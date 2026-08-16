#pragma once

#include "../../include/airplayc/airplayc.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airplayc::audio {

struct AlacDecoderConfig {
    uint32_t sample_rate = 44100;
    uint32_t samples_per_frame = 352;
    uint16_t channels = 2;
    uint16_t bits_per_sample = 16;
};

class AlacDecoder {
public:
    AlacDecoder();
    ~AlacDecoder();

    AlacDecoder(const AlacDecoder&) = delete;
    AlacDecoder& operator=(const AlacDecoder&) = delete;

    bool configure(const AlacDecoderConfig& config, std::string& error);
    bool decode_frame(const uint8_t* data,
                      size_t bytes,
                      std::vector<int16_t>& pcm,
                      size_t& frame_count,
                      std::string& error);

    AudioFormat output_format() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace airplayc::audio
