#pragma once

// airplayc - C++ AirPlay audio receiver library for Windows.
//
// The library exposes a Spotify-library-like callback surface: the host starts
// one receiver session, receives paced decoded PCM frames, and gets metadata /
// lifecycle events from the AirPlay client. V1 is audio-only.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace airplayc {

struct AudioFormat {
    uint32_t sample_rate = 44100;
    uint16_t channels = 2;
    uint16_t bits_per_sample = 16;
};

struct Metadata {
    std::string title;
    std::string artist;
    std::string album;
    std::string genre;
    uint64_t duration_ms = 0;
};

struct PlaybackProgress {
    uint64_t start_rtp_time = 0;
    uint64_t current_rtp_time = 0;
    uint64_t end_rtp_time = 0;
    double position_seconds = 0.0;
    double duration_seconds = 0.0;
};

enum class EventType : uint8_t {
    ReceiverStarted,
    ReceiverStopped,
    ClientConnected,
    ClientDisconnected,
    PlaybackStarted,
    PlaybackPaused,
    PlaybackStopped,
    MetadataChanged,
    CoverArtChanged,
    VolumeChanged,
    StreamError,
    ProtocolMessage,
};

enum class ErrorCode : uint8_t {
    None = 0,
    InvalidConfig,
    NetworkError,
    DiscoveryError,
    ProtocolError,
    CryptoUnsupported,
    AudioUnsupported,
    Internal,
};

struct Event {
    EventType type = EventType::ProtocolMessage;
    std::string detail;
};

// pcm points to interleaved signed 16-bit samples.
// frame_count is multi-channel frames, so sample count is
// frame_count * format.channels.
//
// Threading: invoked on the library stream thread. One callback is active at a
// time per Session. Host code must not call Session methods from inside this
// callback. Return false to apply backpressure; the same frame is retried until
// accepted or the stream stops.
using AudioCallback = std::function<bool(const int16_t* pcm,
                                         size_t frame_count,
                                         const AudioFormat& format)>;

using EventCallback = std::function<void(const Event& event)>;
using MetadataCallback = std::function<void(const Metadata& metadata)>;
using CoverArtCallback = std::function<void(const uint8_t* data,
                                            size_t bytes,
                                            const std::string& mime_type)>;
using VolumeCallback = std::function<void(float db)>;
using ProgressCallback = std::function<void(const PlaybackProgress& progress)>;

struct Config {
    std::string device_name = "airplayc";
    std::string device_id;
    // Advertised identity used by DNS-SD and /info. The default model uses the
    // broadly compatible speaker device class.
    std::string manufacturer = "airplayc";
    std::string model = "Speaker";
    std::string source_version = "220.68";
    std::string firmware_version;
    // DNS-SD feature flags are visible before connection and influence iOS'
    // picker classification. info_feature_flags is returned from RTSP /info;
    // leave it empty to use feature_flags.
    std::string feature_flags = "0x527FFEE6,0x0";
    std::string info_feature_flags;
    std::string raop_codecs = "0,1,2,3";
    std::string raop_encryption_types = "0,3,5";
    std::string cache_dir;
    // Optional IPv4 address to advertise in DNS-SD A records, e.g. the Wi-Fi
    // or Ethernet address reachable by the phone. Leave empty to let Windows
    // choose, which can pick a virtual adapter on developer machines.
    std::string advertise_ipv4;

    // 0 lets the OS pick an available RTSP port. The selected port can be read
    // through Session::rtsp_port() after start().
    uint16_t rtsp_port = 0;

    // Optional explicit UDP ports for RTP audio, control, and timing. Zero uses
    // the receiver defaults (6000, 6001, and 7011 respectively).
    uint16_t audio_rtp_port = 0;
    uint16_t audio_control_port = 0;
    uint16_t timing_port = 0;

    AudioCallback on_audio;
    EventCallback on_event;
    MetadataCallback on_metadata;
    CoverArtCallback on_cover_art;
    VolumeCallback on_volume;
    ProgressCallback on_progress;

    bool enable_discovery = true;
    // Initial volume advertised to AirPlay clients until the client sends its
    // first volume SET_PARAMETER. AirPlay uses dB, typically 0.0 down to about
    // -30.0, with very low values used for mute.
    float initial_volume_db = -20.0f;

};

class Session {
public:
    static std::unique_ptr<Session> create(const Config& config);
    ~Session();

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    bool start();
    void stop();
    bool is_running() const;

    ErrorCode last_error() const;
    std::string last_error_message() const;
    uint16_t rtsp_port() const;
    std::string device_id() const;

    bool pause();
    bool resume();
    bool toggle_pause();
    bool next_track();
    bool previous_track();
    // Ask the connected AirPlay sender to seek to an absolute playback
    // position, in milliseconds. Returns false when no sender/Active-Remote is
    // known or the command fails. DACP seek is sender-dependent: some senders
    // ignore the request, in which case this returns the sender's result.
    bool seek(uint32_t position_ms);
    bool set_volume_db(float db);
    bool set_volume_percent(uint8_t percent);

private:
    Session();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace airplayc
