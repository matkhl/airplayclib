#pragma once

#include "../../include/airplayc/airplayc.h"
#include "alac_decoder.h"
#include "../rtp/rtp_receiver.h"

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace airplayc::audio {

struct RaopCryptoConfig {
    uint64_t encryption_type = 0;
    uint64_t fairplay_setup_mode = 0;
    std::vector<uint8_t> key_message;
    std::vector<uint8_t> ekey;
    std::vector<uint8_t> eiv;
    std::vector<uint8_t> group_encryption_key;
};

struct RaopStreamConfig {
    uint64_t audio_format = 0;
    uint64_t compression_type = 0;
    uint64_t sample_rate = 0;
    uint64_t samples_per_frame = 0;
    uint64_t payload_type = 0;
    std::vector<uint8_t> shared_key;
};

struct RaopDecryptStats {
    uint64_t packets_seen = 0;
    uint64_t packets_decrypted = 0;
    uint64_t alac_like_frames = 0;
    uint64_t alac_frames_decoded = 0;
    uint64_t alac_decode_failures = 0;
    uint64_t audio_frames_queued = 0;
    uint64_t audio_frames_delivered = 0;
    uint64_t audio_callback_retries = 0;
    uint64_t audio_queue_drops = 0;
    uint64_t aac_eld_like_frames = 0;
    uint64_t unknown_frames = 0;
    uint64_t decrypt_failures = 0;
};

class RaopAudioDecryptor {
public:
    using LogCallback = std::function<void(const std::string& detail)>;
    using AlacFrameCallback = std::function<void(const uint8_t* data, size_t bytes, uint32_t rtp_timestamp)>;

    ~RaopAudioDecryptor();

    void set_log_callback(LogCallback callback);
    void set_alac_frame_callback(AlacFrameCallback callback);
    void set_audio_callback(AudioCallback callback);
    void reset();
    void configure_crypto(const RaopCryptoConfig& config);
    void configure_stream(const RaopStreamConfig& config);
    void handle_packet(const rtp::CapturedPacket& packet);
    RaopDecryptStats stats() const;
    bool key_ready() const;
    std::string last_error() const;

private:
    struct QueuedPcmFrame {
        std::vector<int16_t> pcm;
        size_t frame_count = 0;
        AudioFormat format;
    };

    void log_once_waiting_for_key(const std::string& detail);
    void handle_decrypted_frame(const std::vector<uint8_t>& frame, uint32_t rtp_timestamp);
    void start_output_worker();
    void stop_output_worker();
    void clear_output_queue();
    void enqueue_pcm(std::vector<int16_t> pcm, size_t frame_count, const AudioFormat& format);
    void output_loop();

    LogCallback log_;
    AlacFrameCallback on_alac_frame_;
    AudioCallback on_audio_;
    RaopCryptoConfig crypto_;
    RaopStreamConfig stream_;
    RaopDecryptStats stats_;
    mutable std::mutex stats_mutex_;
    AlacDecoder alac_decoder_;
    std::vector<uint8_t> aes_key_;
    std::vector<uint8_t> direct_stream_key_;
    std::string last_error_;
    std::mutex output_mutex_;
    std::condition_variable output_cv_;
    std::queue<QueuedPcmFrame> output_queue_;
    std::thread output_thread_;
    bool output_running_ = false;
    bool have_crypto_ = false;
    bool have_stream_ = false;
    bool waiting_for_key_logged_ = false;
};

} // namespace airplayc::audio
