#include "rtp_receiver.h"

#include <array>
#include <cstdint>
#include <utility>
#include <sstream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>

namespace airplayc::rtp {

bool parse_header(const uint8_t* data, size_t bytes, PacketInfo& info, size_t& payload_offset) {
    if (!data || bytes < 12) {
        return false;
    }
    const uint8_t version = data[0] >> 6;
    if (version != 2) {
        return false;
    }
    const uint8_t csrc_count = data[0] & 0x0f;
    payload_offset = 12 + static_cast<size_t>(csrc_count) * 4;
    if (bytes < payload_offset) {
        return false;
    }
    info.payload_type = data[1] & 0x7f;
    info.sequence = static_cast<uint16_t>((data[2] << 8) | data[3]);
    info.timestamp = (static_cast<uint32_t>(data[4]) << 24) |
                     (static_cast<uint32_t>(data[5]) << 16) |
                     (static_cast<uint32_t>(data[6]) << 8) |
                     static_cast<uint32_t>(data[7]);
    info.ssrc = (static_cast<uint32_t>(data[8]) << 24) |
                (static_cast<uint32_t>(data[9]) << 16) |
                (static_cast<uint32_t>(data[10]) << 8) |
                static_cast<uint32_t>(data[11]);
    return true;
}

std::string describe_packet(const PacketInfo& info) {
    std::ostringstream out;
    out << "rtp seq=" << info.sequence << " ts=" << info.timestamp
        << " ssrc=" << info.ssrc
        << " pt=" << static_cast<unsigned>(info.payload_type);
    return out.str();
}

namespace {

class WsaRuntime {
public:
    WsaRuntime() {
        WSADATA data{};
        ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }

    ~WsaRuntime() {
        if (ok_) {
            WSACleanup();
        }
    }

    bool ok() const { return ok_; }

private:
    bool ok_ = false;
};

std::string winsock_error(const char* action) {
    std::ostringstream out;
    out << action << " failed with WSA error " << WSAGetLastError();
    return out.str();
}

void close_socket(uintptr_t& socket_handle) {
    if (socket_handle != 0) {
        closesocket(static_cast<SOCKET>(socket_handle));
        socket_handle = 0;
    }
}

} // namespace

UdpProbe::UdpProbe() = default;

UdpProbe::~UdpProbe() {
    stop();
}

bool UdpProbe::start(uint16_t data_port,
                     uint16_t control_port,
                     uint16_t timing_port,
                     LogCallback log,
                     PacketCallback audio_packet,
                     std::string& error) {
    stop();

    static WsaRuntime wsa;
    if (!wsa.ok()) {
        error = "WSAStartup failed";
        return false;
    }

    log_ = std::move(log);
    audio_packet_ = std::move(audio_packet);

    if (!bind_socket(data_, data_port, "audio-data", error) ||
        !bind_socket(control_, control_port, "audio-control", error) ||
        !bind_socket(timing_, timing_port, "audio-timing", error)) {
        stop();
        return false;
    }

    running_.store(true);
    data_.thread = std::thread([this] { receive_loop(&data_); });
    control_.thread = std::thread([this] { receive_loop(&control_); });
    timing_.thread = std::thread([this] { receive_loop(&timing_); });
    return true;
}

void UdpProbe::stop() {
    running_.store(false);
    close_socket(data_.socket_handle);
    close_socket(control_.socket_handle);
    close_socket(timing_.socket_handle);

    if (data_.thread.joinable()) {
        data_.thread.join();
    }
    if (control_.thread.joinable()) {
        control_.thread.join();
    }
    if (timing_.thread.joinable()) {
        timing_.thread.join();
    }

    audio_packet_ = {};
}

bool UdpProbe::is_running() const {
    return running_.load();
}

bool UdpProbe::bind_socket(SocketState& state, uint16_t port, std::string name, std::string& error) {
    SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == INVALID_SOCKET) {
        error = winsock_error("socket");
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        error = winsock_error(("bind udp " + name + ":" + std::to_string(port)).c_str());
        closesocket(socket);
        return false;
    }

    DWORD timeout_ms = 500;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    state.socket_handle = static_cast<uintptr_t>(socket);
    state.port = port;
    state.name = std::move(name);
    return true;
}

void UdpProbe::receive_loop(SocketState* state) {
    if (log_) {
        log_("udp " + state->name + " listening on " + std::to_string(state->port));
    }

    std::array<uint8_t, 2048> buffer{};
    while (running_.load()) {
        sockaddr_in remote{};
        int remote_len = sizeof(remote);
        const int received = recvfrom(static_cast<SOCKET>(state->socket_handle),
                                      reinterpret_cast<char*>(buffer.data()),
                                      static_cast<int>(buffer.size()),
                                      0,
                                      reinterpret_cast<sockaddr*>(&remote),
                                      &remote_len);
        if (received <= 0) {
            continue;
        }
        state->packets_received += 1;

        char remote_ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &remote.sin_addr, remote_ip, sizeof(remote_ip));

        std::ostringstream out;
        out << "udp " << state->name << " packet bytes=" << received
            << " from=" << remote_ip << ':' << ntohs(remote.sin_port);
        PacketInfo info;
        size_t payload_offset = 0;
        if (parse_header(buffer.data(), static_cast<size_t>(received), info, payload_offset)) {
            out << ' ' << describe_packet(info)
                << " payload=" << (static_cast<size_t>(received) - payload_offset);
            if (state->name == "audio-data") {
                if (audio_packet_) {
                    CapturedPacket packet;
                    packet.info = info;
                    packet.datagram.assign(buffer.begin(), buffer.begin() + received);
                    packet.payload_offset = payload_offset;
                    audio_packet_(packet);
                }
            }
        }
        const bool should_log_packet = state->packets_received <= 4 ||
                                       state->packets_received % 256 == 0 ||
                                       state->name != "audio-data";
        if (log_ && should_log_packet) {
            log_(out.str());
        }
    }
}

} // namespace airplayc::rtp
