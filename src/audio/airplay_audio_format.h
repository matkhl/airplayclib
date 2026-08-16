#pragma once

#include <cstdint>
#include <string>

namespace airplayc::audio {

struct AirPlayCodecInfo {
    std::string codec;
    uint32_t sample_rate = 0;
    uint16_t bits_per_sample = 0;
    uint16_t channels = 0;
    bool known = false;
};

AirPlayCodecInfo describe_airplay_format(uint64_t audio_format,
                                          uint64_t compression_type,
                                          uint64_t sample_rate);
std::string format_airplay_codec_info(const AirPlayCodecInfo& info);

} // namespace airplayc::audio
