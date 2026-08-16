#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace airplayc::discovery {

class UdpMdnsAdvertiser;

class DnssdAdvertiser {
public:
    DnssdAdvertiser();
    ~DnssdAdvertiser();

    DnssdAdvertiser(const DnssdAdvertiser&) = delete;
    DnssdAdvertiser& operator=(const DnssdAdvertiser&) = delete;

    bool start(const std::string& device_name,
               const std::string& device_id,
               const std::string& manufacturer,
               const std::string& model,
               const std::string& source_version,
               const std::string& firmware_version,
               const std::string& feature_flags,
               const std::string& raop_codecs,
               const std::string& raop_encryption_types,
               const std::string& advertise_ipv4,
               uint16_t rtsp_port,
               std::string& error);
    void stop();
    bool is_running() const;

private:
    bool register_service(const std::wstring& instance,
                          uint16_t port,
                          const std::string& advertise_ipv4,
                          const std::vector<std::wstring>& txt,
                          std::string& error);

    void* raop_cancel_ = nullptr;
    void* airplay_cancel_ = nullptr;
    void* raop_instance_ = nullptr;
    void* airplay_instance_ = nullptr;
    std::unique_ptr<UdpMdnsAdvertiser> udp_mdns_;
    bool running_ = false;
};

} // namespace airplayc::discovery
