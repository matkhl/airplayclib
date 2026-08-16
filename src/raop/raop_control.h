#pragma once

#include "../rtsp/rtsp_message.h"
#include "../../include/airplayc/airplayc.h"

#include <functional>
#include <cstdint>
#include <string>
#include <vector>

namespace airplayc::raop {

struct ReceiverInfo {
    std::string device_name;
    std::string device_id;
    std::string manufacturer;
    std::string model;
    std::string source_version;
    std::string firmware_version;
    std::string feature_flags;
    std::string info_feature_flags;
    uint16_t audio_data_port = 0;
    uint16_t audio_control_port = 0;
    uint16_t timing_port = 0;
    float initial_volume_db = -20.0f;
};

struct SessionCryptoInfo {
    uint64_t encryption_type = 0;
    uint64_t fairplay_setup_mode = 0;
    uint16_t timing_port = 0;
    std::string session_uuid;
    std::string source_version;
    std::vector<uint8_t> eiv;
    std::vector<uint8_t> ekey;
    std::vector<uint8_t> group_encryption_key;
    std::vector<uint8_t> fairplay_key_message;
    std::vector<uint8_t> raw_setup_plist;
};

struct AudioStreamInfo {
    uint64_t audio_format = 0;
    uint64_t compression_type = 0;
    uint64_t sample_rate = 0;
    uint64_t samples_per_frame = 0;
    uint64_t payload_type = 0;
    uint16_t client_control_port = 0;
    std::string audio_mode;
    std::vector<uint8_t> shared_key;
    std::vector<uint8_t> raw_setup_plist;
};

struct ControlCallbacks {
    std::function<void(const std::string& detail)> on_protocol;
    std::function<void(const SessionCryptoInfo& info)> on_session_crypto;
    std::function<void(const AudioStreamInfo& info)> on_audio_stream;
    std::function<void()> on_playback_started;
    std::function<void()> on_playback_paused;
    std::function<void()> on_playback_stopped;
    std::function<void(float db)> on_volume_changed;
    std::function<void(const PlaybackProgress& progress)> on_progress;
    std::function<void(const Metadata& metadata)> on_metadata;
    std::function<void(const uint8_t* data, size_t bytes, const std::string& mime_type)> on_cover_art;
    std::function<void(const std::string& detail)> on_error;
};

class ControlSession {
public:
    ControlSession(ReceiverInfo info, ControlCallbacks callbacks);

    rtsp::Response handle(const rtsp::Request& request);

private:
    std::string options_body() const;
    std::string server_info_body() const;
    std::string info_plist_body() const;
    std::string stream_setup_response_body() const;
    rtsp::Response handle_fp_setup(const rtsp::Request& request);
    std::string request_trace(const rtsp::Request& request) const;
    void set_current_volume(float volume_db);

    ReceiverInfo info_;
    ControlCallbacks callbacks_;
    uint8_t last_fp_setup_mode_ = 0;
    std::vector<uint8_t> last_fp_setup_key_message_;
    SessionCryptoInfo announced_crypto_;
    AudioStreamInfo announced_stream_;
    bool have_announced_crypto_ = false;
    bool have_announced_stream_ = false;
    bool playback_active_ = false;
    float current_volume_db_ = -20.0f;
    uint64_t stream_sample_rate_ = 44100;
};

} // namespace airplayc::raop
