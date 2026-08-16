#include "../../include/airplayc/airplayc.h"

#include "../audio/raop_audio_decryptor.h"
#include "../discovery/dnssd_advertiser.h"
#include "../net/dacp_client.h"
#include "../net/tcp_server.h"
#include "../raop/raop_control.h"
#include "../rtp/rtp_receiver.h"
#include "../rtsp/rtsp_message.h"
#include "../utils/string_utils.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <vector>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>

namespace airplayc {

struct Session::Impl {
    explicit Impl(Config cfg)
        : config(std::move(cfg)),
          device(config.device_id.empty() ? utils::stable_device_id(config.device_name) : config.device_id) {
        configure_audio_decryptor_callbacks();
    }

    Config config;
    std::string device;
    mutable std::mutex mutex;
    ErrorCode last_error = ErrorCode::None;
    std::string last_error_message;
    std::atomic<bool> running{false};
    net::TcpServer server;
    discovery::DnssdAdvertiser discovery;
    rtp::UdpProbe udp_probe;
    uint16_t audio_data_port = 6000;
    uint16_t audio_control_port = 6001;
    uint16_t timing_port = 7011;
    raop::SessionCryptoInfo session_crypto;
    raop::AudioStreamInfo audio_stream;
    audio::RaopAudioDecryptor audio_decryptor;
    bool playback_active = false;
    net::DacpRemoteInfo dacp_remote;

    void configure_audio_decryptor_callbacks() {
        audio_decryptor.set_log_callback([this](const std::string& detail) {
            emit(EventType::ProtocolMessage, detail);
        });
        audio_decryptor.set_audio_callback(config.on_audio);
    }

    void set_error(ErrorCode code, std::string message) {
        std::lock_guard lock(mutex);
        last_error = code;
        last_error_message = std::move(message);
    }

    void emit(EventType type, std::string detail = {}) const {
        if (config.on_event) {
            config.on_event(Event{type, std::move(detail)});
        }
    }

    void mark_playback_started_locked() {
        if (playback_active) {
            return;
        }
        playback_active = true;
        emit(EventType::PlaybackStarted);
    }

    void mark_playback_stopped_locked() {
        if (!playback_active) {
            return;
        }
        playback_active = false;
        emit(EventType::PlaybackStopped);
    }

    void handle_client(uintptr_t socket_handle, const std::string& remote) {
        SOCKET socket = static_cast<SOCKET>(socket_handle);
        emit(EventType::ClientConnected, remote);

        raop::ControlSession control({
            config.device_name,
            device,
            config.manufacturer,
            config.model,
            config.source_version,
            config.firmware_version,
            config.feature_flags,
            config.info_feature_flags,
            audio_data_port,
            audio_control_port,
            timing_port,
            config.initial_volume_db,
        }, {
            [this](const std::string& detail) { emit(EventType::ProtocolMessage, detail); },
            [this](const raop::SessionCryptoInfo& info) {
                std::lock_guard lock(mutex);
                session_crypto = info;
                audio_stream = {};
                audio_decryptor.reset();
                audio_decryptor.configure_crypto(audio::RaopCryptoConfig{
                    info.encryption_type,
                    info.fairplay_setup_mode,
                    info.fairplay_key_message,
                    info.ekey,
                    info.eiv,
                    info.group_encryption_key,
                });
            },
            [this](const raop::AudioStreamInfo& info) {
                std::lock_guard lock(mutex);
                audio_stream = info;
                audio_decryptor.configure_stream(audio::RaopStreamConfig{
                    info.audio_format,
                    info.compression_type,
                    info.sample_rate,
                    info.samples_per_frame,
                    info.payload_type,
                    info.shared_key,
                });
            },
            [this] {
                std::lock_guard lock(mutex);
                mark_playback_started_locked();
            },
            [this] {
                emit(EventType::PlaybackPaused);
            },
            [this] {
                std::lock_guard lock(mutex);
                mark_playback_stopped_locked();
            },
            [this](float db) {
                if (config.on_volume) {
                    config.on_volume(db);
                }
                emit(EventType::VolumeChanged, std::to_string(db));
            },
            [this](const PlaybackProgress& progress) {
                if (config.on_progress) {
                    config.on_progress(progress);
                }
            },
            [this](const Metadata& metadata) {
                if (config.on_metadata) {
                    config.on_metadata(metadata);
                }
                emit(EventType::MetadataChanged, metadata.artist + " - " + metadata.title);
            },
            [this](const uint8_t* data, size_t bytes, const std::string& mime_type) {
                if (config.on_cover_art) {
                    config.on_cover_art(data, bytes, mime_type);
                }
                emit(EventType::CoverArtChanged, std::to_string(bytes) + " bytes " + mime_type);
            },
            [this](const std::string& detail) {
                set_error(ErrorCode::ProtocolError, detail);
                emit(EventType::StreamError, detail);
            },
        });

        std::string buffer;
        char chunk[8192]{};
        while (running.load()) {
            const int received = recv(socket, chunk, sizeof(chunk), 0);
            if (received <= 0) {
                break;
            }
            buffer.append(chunk, static_cast<size_t>(received));

            while (true) {
                rtsp::Request request;
                size_t consumed = 0;
                if (!rtsp::try_parse_request(buffer, request, consumed)) {
                    break;
                }
                buffer.erase(0, consumed);
                {
                    std::lock_guard lock(mutex);
                    const auto dacp_id = request.header("DACP-ID");
                    const auto active_remote = request.header("Active-Remote");
                    if (!dacp_id.empty()) {
                        dacp_remote.dacp_id = dacp_id;
                    }
                    if (!active_remote.empty()) {
                        dacp_remote.active_remote = active_remote;
                    }
                    if (!remote.empty()) {
                        dacp_remote.fallback_host = remote;
                    }
                    dacp_remote.local_query_address = config.advertise_ipv4;
                }
                auto response = control.handle(request);
                const auto wire = response.serialize();
                send(socket, wire.data(), static_cast<int>(wire.size()), 0);
            }
        }

        emit(EventType::ClientDisconnected, remote);
    }

    bool send_control_command(const std::string& command) {
        net::DacpRemoteInfo remote;
        {
            std::lock_guard lock(mutex);
            remote = dacp_remote;
        }

        std::string error;
        if (!net::send_dacp_command(remote, command, error)) {
            set_error(ErrorCode::ProtocolError, error);
            emit(EventType::StreamError, error);
            return false;
        }
        emit(EventType::ProtocolMessage, "sent DACP command: " + command);
        return true;
    }
};

Session::Session() = default;

Session::~Session() = default;

std::unique_ptr<Session> Session::create(const Config& config) {
    auto session = std::unique_ptr<Session>(new Session());
    session->impl_ = std::make_unique<Impl>(config);
    return session;
}

bool Session::start() {
    if (!impl_) {
        return false;
    }
    if (impl_->running.exchange(true)) {
        return true;
    }

    if (impl_->config.device_name.empty()) {
        impl_->running.store(false);
        impl_->set_error(ErrorCode::InvalidConfig, "device_name is required");
        return false;
    }

    impl_->audio_data_port = impl_->config.audio_rtp_port == 0 ? 6000 : impl_->config.audio_rtp_port;
    impl_->audio_control_port = impl_->config.audio_control_port == 0 ? 6001 : impl_->config.audio_control_port;
    impl_->timing_port = impl_->config.timing_port == 0 ? 7011 : impl_->config.timing_port;

    std::string error;
    if (!impl_->udp_probe.start(impl_->audio_data_port,
                                impl_->audio_control_port,
                                impl_->timing_port,
                                [impl = impl_.get()](const std::string& detail) {
                                    impl->emit(EventType::ProtocolMessage, detail);
                                },
                                [impl = impl_.get()](const rtp::CapturedPacket& packet) {
                                    std::lock_guard lock(impl->mutex);
                                    const auto before = impl->audio_decryptor.stats();
                                    impl->audio_decryptor.handle_packet(packet);
                                    const auto stats = impl->audio_decryptor.stats();
                                    if (stats.alac_frames_decoded > before.alac_frames_decoded) {
                                        impl->mark_playback_started_locked();
                                    }
                                },
                                error)) {
        impl_->running.store(false);
        impl_->set_error(ErrorCode::NetworkError, error);
        return false;
    }

    if (!impl_->server.start(impl_->config.rtsp_port,
                             [impl = impl_.get()](uintptr_t socket_handle, const std::string& remote) {
                                 impl->handle_client(socket_handle, remote);
                             },
                             error)) {
        impl_->udp_probe.stop();
        impl_->running.store(false);
        impl_->set_error(ErrorCode::NetworkError, error);
        return false;
    }

    if (impl_->config.enable_discovery) {
        if (!impl_->discovery.start(impl_->config.device_name,
                                    impl_->device,
                                    impl_->config.manufacturer,
                                    impl_->config.model,
                                    impl_->config.source_version,
                                    impl_->config.firmware_version,
                                    impl_->config.feature_flags,
                                    impl_->config.raop_codecs,
                                    impl_->config.raop_encryption_types,
                                    impl_->config.advertise_ipv4,
                                    impl_->server.port(),
                                    error)) {
            impl_->server.stop();
            impl_->udp_probe.stop();
            impl_->running.store(false);
            impl_->set_error(ErrorCode::DiscoveryError, error);
            return false;
        }
    }

    impl_->set_error(ErrorCode::None, {});
    impl_->emit(EventType::ReceiverStarted, std::to_string(impl_->server.port()));
    return true;
}

void Session::stop() {
    if (!impl_) {
        return;
    }
    if (!impl_->running.exchange(false)) {
        return;
    }
    impl_->discovery.stop();
    impl_->server.stop();
    impl_->udp_probe.stop();
    impl_->emit(EventType::ReceiverStopped);
}

bool Session::is_running() const {
    return impl_ && impl_->running.load();
}

ErrorCode Session::last_error() const {
    if (!impl_) {
        return ErrorCode::Internal;
    }
    std::lock_guard lock(impl_->mutex);
    return impl_->last_error;
}

std::string Session::last_error_message() const {
    if (!impl_) {
        return "session is not initialized";
    }
    std::lock_guard lock(impl_->mutex);
    return impl_->last_error_message;
}

uint16_t Session::rtsp_port() const {
    return impl_ ? impl_->server.port() : 0;
}

std::string Session::device_id() const {
    return impl_ ? impl_->device : std::string{};
}

bool Session::pause() {
    return impl_ && impl_->send_control_command("pause");
}

bool Session::resume() {
    return impl_ && impl_->send_control_command("play");
}

bool Session::toggle_pause() {
    return impl_ && impl_->send_control_command("playpause");
}

bool Session::next_track() {
    return impl_ && impl_->send_control_command("nextitem");
}

bool Session::previous_track() {
    return impl_ && impl_->send_control_command("previtem");
}

bool Session::seek(uint32_t position_ms) {
    // DACP seek is a setproperty GET, analogous to the volume path above, but
    // the property lives under the dacp. prefix and the unit is milliseconds.
    return impl_ && impl_->send_control_command(
                        "setproperty?dacp.playingtime=" +
                        std::to_string(position_ms));
}

bool Session::set_volume_db(float db) {
    if (!impl_) {
        return false;
    }

    const float clamped = std::clamp(db, -30.0f, 0.0f);
    std::ostringstream value;
    value.imbue(std::locale::classic());
    value << std::fixed << std::setprecision(6) << clamped;
    return impl_->send_control_command("setproperty?dmcp.device-volume=" + value.str());
}

bool Session::set_volume_percent(uint8_t percent) {
    if (!impl_) {
        return false;
    }

    const auto clamped = static_cast<unsigned>(std::min<uint8_t>(percent, 100));
    const float db = (static_cast<float>(clamped) / 100.0f - 1.0f) * 30.0f;
    return set_volume_db(db);
}

}
