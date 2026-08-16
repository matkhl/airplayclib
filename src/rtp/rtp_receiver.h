#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <atomic>
#include <cstddef>
#include <vector>

namespace airplayc::rtp {

struct PacketInfo {
    uint16_t sequence = 0;
    uint32_t timestamp = 0;
    uint32_t ssrc = 0;
    uint8_t payload_type = 0;
};

struct CapturedPacket {
    PacketInfo info;
    std::vector<uint8_t> datagram;
    size_t payload_offset = 0;
};

bool parse_header(const uint8_t* data, size_t bytes, PacketInfo& info, size_t& payload_offset);
std::string describe_packet(const PacketInfo& info);

class UdpProbe {
public:
    using LogCallback = std::function<void(const std::string& detail)>;
    using PacketCallback = std::function<void(const CapturedPacket& packet)>;

    UdpProbe();
    ~UdpProbe();

    UdpProbe(const UdpProbe&) = delete;
    UdpProbe& operator=(const UdpProbe&) = delete;

    bool start(uint16_t data_port,
               uint16_t control_port,
               uint16_t timing_port,
               LogCallback log,
               PacketCallback audio_packet,
               std::string& error);
    void stop();
    bool is_running() const;

private:
    struct SocketState {
        uintptr_t socket_handle = 0;
        uint16_t port = 0;
        std::string name;
        std::thread thread;
        uint64_t packets_received = 0;
    };

    bool bind_socket(SocketState& state, uint16_t port, std::string name, std::string& error);
    void receive_loop(SocketState* state);

    std::atomic<bool> running_{false};
    LogCallback log_;
    PacketCallback audio_packet_;
    SocketState data_;
    SocketState control_;
    SocketState timing_;
};

} // namespace airplayc::rtp
