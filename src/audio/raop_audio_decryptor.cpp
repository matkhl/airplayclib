#include "raop_audio_decryptor.h"

#include "../crypto/fairplay.h"
#include "payload_crypto.h"

#include <chrono>
#include <mutex>
#include <thread>
#include <utility>

namespace airplayc::audio {
namespace {

bool is_alac_marker(uint8_t marker) {
    return marker == 0x20;
}

bool is_aac_eld_marker(uint8_t marker) {
    return marker == 0x80 || marker == 0x81 || marker == 0x82 ||
           marker == 0x8c || marker == 0x8d || marker == 0x8e;
}

constexpr size_t kMaxQueuedPcmFrames = 256;

} // namespace

RaopAudioDecryptor::~RaopAudioDecryptor() {
    stop_output_worker();
}

void RaopAudioDecryptor::set_log_callback(LogCallback callback) {
    log_ = std::move(callback);
}

void RaopAudioDecryptor::set_alac_frame_callback(AlacFrameCallback callback) {
    on_alac_frame_ = std::move(callback);
}

void RaopAudioDecryptor::set_audio_callback(AudioCallback callback) {
    on_audio_ = std::move(callback);
    if (on_audio_) {
        start_output_worker();
    } else {
        stop_output_worker();
    }
}

void RaopAudioDecryptor::reset() {
    crypto_ = {};
    stream_ = {};
    {
        std::lock_guard lock(stats_mutex_);
        stats_ = {};
    }
    aes_key_.clear();
    direct_stream_key_.clear();
    last_error_.clear();
    have_crypto_ = false;
    have_stream_ = false;
    waiting_for_key_logged_ = false;
    clear_output_queue();
}

void RaopAudioDecryptor::configure_crypto(const RaopCryptoConfig& config) {
    crypto_ = config;
    have_crypto_ = true;
    aes_key_.clear();
    direct_stream_key_.clear();
    {
        std::lock_guard lock(stats_mutex_);
        stats_ = {};
    }
    waiting_for_key_logged_ = false;

    if (config.group_encryption_key.size() == 32) {
        direct_stream_key_ = config.group_encryption_key;
        last_error_.clear();
        if (log_) {
            log_("audio decrypt AirPlay direct group key ready");
        }
        return;
    }

    crypto::FairPlayContext context;
    context.encryption_type = config.encryption_type;
    context.setup_mode = config.fairplay_setup_mode;
    context.key_message = config.key_message;
    context.ekey = config.ekey;
    context.eiv = config.eiv;

    std::string error;
    if (!crypto::unwrap_fairplay_key(context, aes_key_, error)) {
        last_error_ = error;
        if (log_) {
            log_("audio decrypt waiting for FairPlay unwrap: " + error);
        }
        return;
    }

    last_error_.clear();
    if (log_) {
        log_("audio decrypt FairPlay AES key ready");
    }
}

void RaopAudioDecryptor::configure_stream(const RaopStreamConfig& config) {
    stream_ = config;
    have_stream_ = true;
    if (stream_.audio_format == 262144 && stream_.compression_type == 2) {
        AlacDecoderConfig decoder_config;
        decoder_config.sample_rate = stream_.sample_rate == 0 ? 44100 : static_cast<uint32_t>(stream_.sample_rate);
        decoder_config.samples_per_frame = stream_.samples_per_frame == 0 ? 352 : static_cast<uint32_t>(stream_.samples_per_frame);
        decoder_config.channels = 2;
        decoder_config.bits_per_sample = 16;

        std::string error;
        if (!alac_decoder_.configure(decoder_config, error)) {
            last_error_ = error;
            if (log_) {
                log_("ALAC decoder configure failed: " + error);
            }
        } else if (log_) {
            log_("ALAC decoder ready sr=" + std::to_string(decoder_config.sample_rate) +
                 " spf=" + std::to_string(decoder_config.samples_per_frame));
        }
    }
}

void RaopAudioDecryptor::handle_packet(const rtp::CapturedPacket& packet) {
    {
        std::lock_guard lock(stats_mutex_);
        stats_.packets_seen += 1;
    }
    if (!have_crypto_ || !have_stream_) {
        return;
    }
    if (packet.info.payload_type != static_cast<uint8_t>(stream_.payload_type)) {
        return;
    }

    std::vector<uint8_t> stream_key;
    if (stream_.shared_key.size() == 32) {
        stream_key = stream_.shared_key;
    } else if (direct_stream_key_.size() == 32) {
        stream_key = direct_stream_key_;
    }

    DecryptedPayload decrypted;
    std::string error;
    bool ok = false;
    if (stream_key.size() == 32) {
        ok = decrypt_airplay2_payload(packet, stream_key, decrypted, error);
    } else if (aes_key_.size() == 16 && crypto_.eiv.size() == 16) {
        ok = decrypt_raop_aes_cbc_payload(packet, aes_key_, crypto_.eiv, decrypted, error);
    } else {
        log_once_waiting_for_key(last_error_.empty() ? "missing FairPlay AES/direct stream key" : last_error_);
        return;
    }

    if (!ok) {
        {
            std::lock_guard lock(stats_mutex_);
            stats_.decrypt_failures += 1;
        }
        if (last_error_.empty()) {
            last_error_ = error;
        }
        return;
    }

    {
        std::lock_guard lock(stats_mutex_);
        stats_.packets_decrypted += 1;
    }
    handle_decrypted_frame(decrypted.plaintext, decrypted.timestamp);
}

RaopDecryptStats RaopAudioDecryptor::stats() const {
    std::lock_guard lock(stats_mutex_);
    return stats_;
}

bool RaopAudioDecryptor::key_ready() const {
    return aes_key_.size() == 16 || stream_.shared_key.size() == 32 || direct_stream_key_.size() == 32;
}

std::string RaopAudioDecryptor::last_error() const {
    return last_error_;
}

void RaopAudioDecryptor::log_once_waiting_for_key(const std::string& detail) {
    if (waiting_for_key_logged_) {
        return;
    }
    waiting_for_key_logged_ = true;
    if (log_) {
        log_("audio decrypt skipped: " + detail);
    }
}

void RaopAudioDecryptor::handle_decrypted_frame(const std::vector<uint8_t>& frame, uint32_t rtp_timestamp) {
    if (frame.empty()) {
        {
            std::lock_guard lock(stats_mutex_);
            stats_.unknown_frames += 1;
        }
        return;
    }

    if (is_alac_marker(frame[0])) {
        {
            std::lock_guard lock(stats_mutex_);
            stats_.alac_like_frames += 1;
        }
        if (on_alac_frame_) {
            on_alac_frame_(frame.data(), frame.size(), rtp_timestamp);
        }
        if (on_audio_) {
            std::vector<int16_t> pcm;
            size_t frame_count = 0;
            std::string error;
            if (!alac_decoder_.decode_frame(frame.data(), frame.size(), pcm, frame_count, error)) {
                uint64_t decode_failures = 0;
                {
                    std::lock_guard lock(stats_mutex_);
                    stats_.alac_decode_failures += 1;
                    decode_failures = stats_.alac_decode_failures;
                }
                if (last_error_.empty()) {
                    last_error_ = error;
                }
                if (decode_failures <= 4 && log_) {
                    log_("ALAC decode failed: " + error);
                }
                return;
            }

            {
                std::lock_guard lock(stats_mutex_);
                stats_.alac_frames_decoded += 1;
            }
            const auto format = alac_decoder_.output_format();
            enqueue_pcm(std::move(pcm), frame_count, format);
        }
    } else if (is_aac_eld_marker(frame[0])) {
        {
            std::lock_guard lock(stats_mutex_);
            stats_.aac_eld_like_frames += 1;
        }
    } else {
        {
            std::lock_guard lock(stats_mutex_);
            stats_.unknown_frames += 1;
        }
    }
}

void RaopAudioDecryptor::start_output_worker() {
    std::lock_guard lock(output_mutex_);
    if (output_running_) {
        return;
    }
    output_running_ = true;
    output_thread_ = std::thread([this] { output_loop(); });
}

void RaopAudioDecryptor::stop_output_worker() {
    {
        std::lock_guard lock(output_mutex_);
        if (!output_running_) {
            return;
        }
        output_running_ = false;
    }
    output_cv_.notify_all();
    if (output_thread_.joinable()) {
        output_thread_.join();
    }
    clear_output_queue();
}

void RaopAudioDecryptor::clear_output_queue() {
    std::lock_guard lock(output_mutex_);
    std::queue<QueuedPcmFrame> empty;
    output_queue_.swap(empty);
}

void RaopAudioDecryptor::enqueue_pcm(std::vector<int16_t> pcm, size_t frame_count, const AudioFormat& format) {
    bool dropped = false;
    {
        std::lock_guard lock(output_mutex_);
        if (output_queue_.size() >= kMaxQueuedPcmFrames) {
            output_queue_.pop();
            dropped = true;
        }
        output_queue_.push(QueuedPcmFrame{std::move(pcm), frame_count, format});
    }
    {
        std::lock_guard lock(stats_mutex_);
        if (dropped) {
            stats_.audio_queue_drops += 1;
        }
        stats_.audio_frames_queued += 1;
    }
    output_cv_.notify_one();
}

void RaopAudioDecryptor::output_loop() {
    while (true) {
        QueuedPcmFrame frame;
        {
            std::unique_lock lock(output_mutex_);
            output_cv_.wait(lock, [this] {
                return !output_running_ || !output_queue_.empty();
            });
            if (!output_running_ && output_queue_.empty()) {
                break;
            }
            frame = std::move(output_queue_.front());
            output_queue_.pop();
        }

        while (output_running_ && on_audio_ &&
               !on_audio_(frame.pcm.data(), frame.frame_count, frame.format)) {
            {
                std::lock_guard lock(stats_mutex_);
                stats_.audio_callback_retries += 1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (output_running_) {
            std::lock_guard lock(stats_mutex_);
            stats_.audio_frames_delivered += 1;
        }
    }
}

} // namespace airplayc::audio
