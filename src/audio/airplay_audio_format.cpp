#include "airplay_audio_format.h"

#include <sstream>

namespace airplayc::audio {
namespace {

std::string compression_name(uint64_t compression_type) {
    switch (compression_type) {
    case 1:
        return "LPCM";
    case 2:
        return "ALAC";
    case 4:
        return "AAC-LC";
    case 8:
        return "AAC-ELD";
    case 32:
        return "OPUS";
    default:
        return "unknown";
    }
}

} // namespace

AirPlayCodecInfo describe_airplay_format(uint64_t audio_format,
                                          uint64_t compression_type,
                                          uint64_t sample_rate) {
    AirPlayCodecInfo info;
    info.codec = compression_name(compression_type);

    switch (audio_format) {
    case 0x00000004:
        info = {"PCM", 8000, 16, 1, true};
        break;
    case 0x00000008:
        info = {"PCM", 8000, 16, 2, true};
        break;
    case 0x00000010:
        info = {"PCM", 16000, 16, 1, true};
        break;
    case 0x00000020:
        info = {"PCM", 16000, 16, 2, true};
        break;
    case 0x00000040:
        info = {"PCM", 24000, 16, 1, true};
        break;
    case 0x00000080:
        info = {"PCM", 24000, 16, 2, true};
        break;
    case 0x00000100:
        info = {"PCM", 32000, 16, 1, true};
        break;
    case 0x00000200:
        info = {"PCM", 32000, 16, 2, true};
        break;
    case 0x00000400:
        info = {"PCM", 44100, 16, 1, true};
        break;
    case 0x00000800:
        info = {"PCM", 44100, 16, 2, true};
        break;
    case 0x00001000:
        info = {"PCM", 44100, 24, 1, true};
        break;
    case 0x00002000:
        info = {"PCM", 44100, 24, 2, true};
        break;
    case 0x00004000:
        info = {"PCM", 48000, 16, 1, true};
        break;
    case 0x00008000:
        info = {"PCM", 48000, 16, 2, true};
        break;
    case 0x00010000:
        info = {"PCM", 48000, 24, 1, true};
        break;
    case 0x00020000:
        info = {"PCM", 48000, 24, 2, true};
        break;
    case 0x00040000:
        info = {"ALAC", 44100, 16, 2, true};
        break;
    case 0x00080000:
        info = {"ALAC", 44100, 24, 2, true};
        break;
    case 0x00100000:
        info = {"ALAC", 48000, 16, 2, true};
        break;
    case 0x00200000:
        info = {"ALAC", 48000, 24, 2, true};
        break;
    case 0x00400000:
        info = {"AAC-LC", 44100, 0, 2, true};
        break;
    case 0x00800000:
        info = {"AAC-LC", 48000, 0, 2, true};
        break;
    case 0x01000000:
        info = {"AAC-ELD", 44100, 0, 2, true};
        break;
    case 0x02000000:
        info = {"AAC-ELD", 48000, 0, 2, true};
        break;
    case 0x04000000:
        info = {"AAC-ELD", 16000, 0, 1, true};
        break;
    case 0x08000000:
        info = {"AAC-ELD", 24000, 0, 1, true};
        break;
    case 0x10000000:
        info = {"OPUS", 16000, 0, 1, true};
        break;
    case 0x20000000:
        info = {"OPUS", 24000, 0, 1, true};
        break;
    case 0x40000000:
        info = {"OPUS", 48000, 0, 1, true};
        break;
    case 0x80000000:
        info = {"AAC-ELD", 44100, 0, 1, true};
        break;
    default:
        info.sample_rate = static_cast<uint32_t>(sample_rate);
        break;
    }

    if (sample_rate != 0 && info.sample_rate == 0) {
        info.sample_rate = static_cast<uint32_t>(sample_rate);
    }
    return info;
}

std::string format_airplay_codec_info(const AirPlayCodecInfo& info) {
    std::ostringstream out;
    out << "codec=" << info.codec;
    if (info.sample_rate != 0) {
        out << " sampleRate=" << info.sample_rate;
    }
    if (info.bits_per_sample != 0) {
        out << " bits=" << info.bits_per_sample;
    }
    if (info.channels != 0) {
        out << " channels=" << info.channels;
    }
    out << " known=" << (info.known ? "true" : "false");
    return out.str();
}

} // namespace airplayc::audio
