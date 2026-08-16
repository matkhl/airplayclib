#include "dnssd_advertiser.h"

#include "../utils/string_utils.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <windns.h>

namespace airplayc::discovery {
namespace {

constexpr uint16_t kMdnsPort = 5353;
constexpr uint32_t kRecordTtlSeconds = 120;
constexpr const char* kMulticastAddr = "224.0.0.251";
constexpr const char* kRaopServiceType = "_raop._tcp.local";
constexpr const char* kAirPlayServiceType = "_airplay._tcp.local";

using DnsServiceConstructInstanceFn = DNS_SERVICE_INSTANCE*(WINAPI*)(
    PCWSTR, PCWSTR, PIP4_ADDRESS, PIP6_ADDRESS, WORD, WORD, WORD, DWORD,
    PCWSTR*, PCWSTR*);
using DnsServiceRegisterFn = DNS_STATUS(WINAPI*)(
    PDNS_SERVICE_REGISTER_REQUEST, PDNS_SERVICE_CANCEL);
using DnsServiceDeRegisterFn = DNS_STATUS(WINAPI*)(
    PDNS_SERVICE_REGISTER_REQUEST, PDNS_SERVICE_CANCEL);
using DnsServiceFreeInstanceFn = VOID(WINAPI*)(PDNS_SERVICE_INSTANCE);

struct DnsApi {
    HMODULE module = nullptr;
    DnsServiceConstructInstanceFn construct_instance = nullptr;
    DnsServiceRegisterFn register_service = nullptr;
    DnsServiceDeRegisterFn deregister_service = nullptr;
    DnsServiceFreeInstanceFn free_instance = nullptr;
};

bool running_under_wine() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    return ntdll && GetProcAddress(ntdll, "wine_get_version");
}

DnsApi load_dnsapi() {
    DnsApi api;
    api.module = LoadLibraryW(L"dnsapi.dll");
    if (!api.module) {
        return api;
    }
    api.construct_instance = reinterpret_cast<DnsServiceConstructInstanceFn>(
        GetProcAddress(api.module, "DnsServiceConstructInstance"));
    api.register_service = reinterpret_cast<DnsServiceRegisterFn>(
        GetProcAddress(api.module, "DnsServiceRegister"));
    api.deregister_service = reinterpret_cast<DnsServiceDeRegisterFn>(
        GetProcAddress(api.module, "DnsServiceDeRegister"));
    api.free_instance = reinterpret_cast<DnsServiceFreeInstanceFn>(
        GetProcAddress(api.module, "DnsServiceFreeInstance"));
    return api;
}

const DnsApi& dns_api() {
    static const DnsApi api = load_dnsapi();
    return api;
}

std::string win32_error(const char* action, DNS_STATUS status) {
    std::ostringstream out;
    out << action << " failed with DNS status " << status;
    return out.str();
}

struct DnsCompletion {
    HANDLE event = nullptr;
    DWORD status = ERROR_SUCCESS;
    const DnsApi* api = nullptr;
};

void WINAPI service_complete(DWORD status, PVOID context,
                             PDNS_SERVICE_INSTANCE instance) {
    if (auto* completion = static_cast<DnsCompletion*>(context)) {
        if (instance && completion->api && completion->api->free_instance) {
            completion->api->free_instance(instance);
        }
        completion->status = status;
        if (completion->event) {
            SetEvent(completion->event);
        }
    }
}

void WINAPI register_complete(DWORD /*status*/, PVOID context,
                              PDNS_SERVICE_INSTANCE instance) {
    auto* api = static_cast<const DnsApi*>(context);
    if (instance && api && api->free_instance) {
        api->free_instance(instance);
    }
}

void deregister_service(void*& cancel, void*& instance) {
    if (instance) {
        const DnsApi& api = dns_api();
        auto* completion = new DnsCompletion{};
        completion->event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        completion->api = &api;
        DNS_SERVICE_REGISTER_REQUEST request{};
        request.Version = DNS_QUERY_REQUEST_VERSION1;
        request.InterfaceIndex = 0;
        request.pServiceInstance =
            static_cast<PDNS_SERVICE_INSTANCE>(instance);
        request.pRegisterCompletionCallback = service_complete;
        request.pQueryContext = completion;
        request.hCredentials = nullptr;
        request.unicastEnabled = FALSE;
        const DNS_STATUS status = api.deregister_service
                                      ? api.deregister_service(&request, nullptr)
                                      : DNS_ERROR_RCODE_NOT_IMPLEMENTED;
        bool completion_owned = true;
        if ((status == DNS_REQUEST_PENDING || status == ERROR_SUCCESS) &&
            completion->event) {
            const DWORD wait = WaitForSingleObject(completion->event, 1500);
            completion_owned = wait == WAIT_OBJECT_0;
        }
        if (completion_owned) {
            if (completion->event) {
                CloseHandle(completion->event);
            }
            delete completion;
        } else {
            // Late callback may still use the completion pointer. Leak this
            // tiny context instead of risking a use-after-free during source
            // switching; timeout should be exceptional.
            completion->event = nullptr;
        }
        if (api.free_instance) {
            api.free_instance(static_cast<PDNS_SERVICE_INSTANCE>(instance));
        }
        instance = nullptr;
    }
    if (cancel) {
        delete static_cast<DNS_SERVICE_CANCEL*>(cancel);
        cancel = nullptr;
    }
}

std::string colon_device_id(const std::string& device_id) {
    if (device_id.size() < 12) {
        return "00:00:00:00:00:00";
    }

    std::ostringstream out;
    for (size_t i = 0; i < 12; i += 2) {
        if (i != 0) {
            out << ':';
        }
        out << device_id.substr(i, 2);
    }
    return out.str();
}

std::string device_uuid(const std::string& device_id) {
    std::string hex = device_id;
    if (hex.size() < 32) {
        hex.append(32 - hex.size(), '0');
    }
    hex.resize(32);
    hex[12] = '4';
    hex[16] = '8';

    std::ostringstream out;
    out << hex.substr(0, 8) << '-'
        << hex.substr(8, 4) << '-'
        << hex.substr(12, 4) << '-'
        << hex.substr(16, 4) << '-'
        << hex.substr(20, 12);
    return out.str();
}

std::vector<std::wstring> raop_txt(const std::string& model,
                                   const std::string& source_version,
                                   const std::string& firmware_version,
                                   const std::string& feature_flags,
                                   const std::string& raop_codecs,
                                   const std::string& raop_encryption_types) {
    std::vector<std::wstring> txt{
        L"txtvers=1",
        L"ch=2",
        L"cn=" + utils::widen(raop_codecs),
        L"da=true",
        L"et=" + utils::widen(raop_encryption_types),
        L"ft=" + utils::widen(feature_flags),
        L"md=0,1,2",
        L"am=" + utils::widen(model),
        L"rhd=5.6.0.0",
        L"pw=false",
        L"sf=0x4",
        L"sr=44100",
        L"ss=16",
        L"sv=false",
        L"tp=UDP",
        L"vv=2",
        L"vn=65537",
        L"vs=" + utils::widen(source_version),
        L"pk=",
    };
    if (!firmware_version.empty()) {
        txt.push_back(L"fv=" + utils::widen(firmware_version));
    }
    return txt;
}

std::vector<std::wstring> airplay_txt(const std::string& device_id,
                                      const std::string& manufacturer,
                                      const std::string& model,
                                      const std::string& source_version,
                                      const std::string& firmware_version,
                                      const std::string& feature_flags) {
    std::vector<std::wstring> txt{
        L"acl=0",
        L"deviceid=" + utils::widen(colon_device_id(device_id)),
        L"features=" + utils::widen(feature_flags),
        L"flags=0x4",
        L"manufacturer=" + utils::widen(manufacturer),
        L"model=" + utils::widen(model),
        L"pi=" + utils::widen(device_uuid(device_id)),
        L"pk=",
        L"pw=false",
        L"rsf=0x0",
        L"srcvers=" + utils::widen(source_version),
        L"vv=2",
    };
    if (!firmware_version.empty()) {
        txt.push_back(L"fv=" + utils::widen(firmware_version));
    }
    return txt;
}

std::wstring local_host_name() {
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(name, &size) || size == 0) {
        return L"airplayc.local";
    }
    return std::wstring(name, size) + L".local";
}

std::string narrow_ascii(const std::wstring& s) {
    std::string out;
    out.reserve(s.size());
    for (wchar_t ch : s) {
        out.push_back(ch >= 0 && ch <= 0x7f ? static_cast<char>(ch) : '-');
    }
    return out;
}

std::string local_host_name_ascii() {
    char name[256] = {};
    DWORD size = static_cast<DWORD>(sizeof(name));
    if (!GetComputerNameExA(ComputerNameDnsHostname, name, &size) || size == 0) {
        size = static_cast<DWORD>(sizeof(name));
        if (!GetComputerNameA(name, &size) || size == 0) {
            std::strcpy(name, "airplayc");
        }
    }
    std::string label(name);
    for (char& ch : label) {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '-';
        if (!ok) {
            ch = '-';
        }
    }
    while (!label.empty() && label.front() == '-') {
        label.erase(label.begin());
    }
    while (!label.empty() && label.back() == '-') {
        label.pop_back();
    }
    if (label.empty()) {
        label = "airplayc";
    }
    if (label.size() > 63) {
        label.resize(63);
    }
    return label + ".local";
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

void put_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(v & 0xff));
}

void patch_u16(std::vector<uint8_t>& out, size_t pos, uint16_t v) {
    out[pos] = static_cast<uint8_t>((v >> 8) & 0xff);
    out[pos + 1] = static_cast<uint8_t>(v & 0xff);
}

void put_name(std::vector<uint8_t>& out, const std::string& name) {
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        if (dot == std::string::npos) {
            dot = name.size();
        }
        size_t len = dot - start;
        if (len > 0) {
            if (len > 63) {
                len = 63;
            }
            out.push_back(static_cast<uint8_t>(len));
            out.insert(out.end(), name.begin() + start, name.begin() + start + len);
        }
        start = dot + 1;
    }
    out.push_back(0);
}

bool read_name(const uint8_t* data, size_t size, size_t& offset,
               std::string& out) {
    out.clear();
    size_t pos = offset;
    size_t next = offset;
    bool jumped = false;
    int jumps = 0;

    while (pos < size) {
        uint8_t len = data[pos++];
        if (len == 0) {
            if (!jumped) {
                next = pos;
            }
            offset = next;
            return true;
        }
        if ((len & 0xc0) == 0xc0) {
            if (pos >= size || ++jumps > 8) {
                return false;
            }
            uint16_t ptr =
                static_cast<uint16_t>(((len & 0x3f) << 8) | data[pos++]);
            if (ptr >= size) {
                return false;
            }
            if (!jumped) {
                next = pos;
            }
            pos = ptr;
            jumped = true;
            continue;
        }
        if ((len & 0xc0) != 0 || pos + len > size) {
            return false;
        }
        if (!out.empty()) {
            out.push_back('.');
        }
        out.append(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        if (!jumped) {
            next = pos;
        }
    }
    return false;
}

bool is_loopback_ipv4(uint32_t addr_net) {
    const uint32_t addr = ntohl(addr_net);
    return (addr >> 24) == 127;
}

std::vector<uint32_t> local_ipv4_addresses() {
    std::set<uint32_t> unique;

    SOCKET probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (probe != INVALID_SOCKET) {
        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(53);
        InetPtonA(AF_INET, "8.8.8.8", &remote.sin_addr);
        connect(probe, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));

        sockaddr_in local{};
        int len = sizeof(local);
        if (getsockname(probe, reinterpret_cast<sockaddr*>(&local), &len) == 0 &&
            local.sin_addr.s_addr != INADDR_ANY &&
            !is_loopback_ipv4(local.sin_addr.s_addr)) {
            unique.insert(local.sin_addr.s_addr);
        }
        closesocket(probe);
    }

    char host[256] = {};
    if (gethostname(host, sizeof(host)) == 0) {
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host, nullptr, &hints, &res) == 0) {
            for (addrinfo* it = res; it; it = it->ai_next) {
                auto* sin = reinterpret_cast<sockaddr_in*>(it->ai_addr);
                if (sin && sin->sin_addr.s_addr != INADDR_ANY &&
                    !is_loopback_ipv4(sin->sin_addr.s_addr)) {
                    unique.insert(sin->sin_addr.s_addr);
                }
            }
            freeaddrinfo(res);
        }
    }

    return std::vector<uint32_t>(unique.begin(), unique.end());
}

void add_record_header(std::vector<uint8_t>& packet,
                       const std::string& name,
                       uint16_t type,
                       uint16_t klass,
                       uint32_t ttl,
                       size_t& rdlen_pos) {
    put_name(packet, name);
    put_u16(packet, type);
    put_u16(packet, klass);
    put_u32(packet, ttl);
    rdlen_pos = packet.size();
    put_u16(packet, 0);
}

std::vector<uint8_t> encode_txt(const std::vector<std::string>& txt) {
    std::vector<uint8_t> out;
    for (const std::string& item : txt) {
        size_t offset = 0;
        do {
            const size_t len = std::min<size_t>(255, item.size() - offset);
            out.push_back(static_cast<uint8_t>(len));
            out.insert(out.end(), item.begin() + offset, item.begin() + offset + len);
            offset += len;
        } while (offset < item.size());
    }
    if (out.empty()) {
        out.push_back(0);
    }
    return out;
}

void add_ptr_record(std::vector<uint8_t>& packet,
                    const std::string& service_type,
                    const std::string& instance_name,
                    uint32_t ttl) {
    size_t rdlen_pos = 0;
    add_record_header(packet, service_type, 12, 0x0001, ttl, rdlen_pos);
    const size_t rdata_start = packet.size();
    put_name(packet, instance_name);
    patch_u16(packet, rdlen_pos,
              static_cast<uint16_t>(packet.size() - rdata_start));
}

void add_srv_record(std::vector<uint8_t>& packet,
                    const std::string& instance_name,
                    const std::string& host_name,
                    uint16_t port,
                    uint32_t ttl) {
    size_t rdlen_pos = 0;
    add_record_header(packet, instance_name, 33, 0x8001, ttl, rdlen_pos);
    const size_t rdata_start = packet.size();
    put_u16(packet, 0);
    put_u16(packet, 0);
    put_u16(packet, port);
    put_name(packet, host_name);
    patch_u16(packet, rdlen_pos,
              static_cast<uint16_t>(packet.size() - rdata_start));
}

void add_txt_record(std::vector<uint8_t>& packet,
                    const std::string& instance_name,
                    const std::vector<std::string>& txt,
                    uint32_t ttl) {
    size_t rdlen_pos = 0;
    add_record_header(packet, instance_name, 16, 0x8001, ttl, rdlen_pos);
    const size_t rdata_start = packet.size();
    const auto encoded = encode_txt(txt);
    packet.insert(packet.end(), encoded.begin(), encoded.end());
    patch_u16(packet, rdlen_pos,
              static_cast<uint16_t>(packet.size() - rdata_start));
}

void add_a_record(std::vector<uint8_t>& packet,
                  const std::string& host_name,
                  uint32_t ip,
                  uint32_t ttl) {
    size_t rdlen_pos = 0;
    add_record_header(packet, host_name, 1, 0x8001, ttl, rdlen_pos);
    const size_t rdata_start = packet.size();
    packet.insert(packet.end(),
                  reinterpret_cast<const uint8_t*>(&ip),
                  reinterpret_cast<const uint8_t*>(&ip) + 4);
    patch_u16(packet, rdlen_pos,
              static_cast<uint16_t>(packet.size() - rdata_start));
}

std::vector<uint8_t> build_response_packet(const std::string& raop_instance,
                                           const std::string& airplay_instance,
                                           const std::string& host_name,
                                           uint16_t port,
                                           const std::vector<std::string>& raop_txt_items,
                                           const std::vector<std::string>& airplay_txt_items,
                                           const std::vector<uint32_t>& ips,
                                           uint32_t ttl) {
    std::vector<uint8_t> packet;
    packet.reserve(1200);

    put_u16(packet, 0);
    put_u16(packet, 0x8400);
    put_u16(packet, 0);
    const uint16_t answer_count =
        static_cast<uint16_t>(6 + static_cast<uint16_t>(ips.size()));
    put_u16(packet, answer_count);
    put_u16(packet, 0);
    put_u16(packet, 0);

    add_ptr_record(packet, kRaopServiceType, raop_instance, ttl);
    add_ptr_record(packet, kAirPlayServiceType, airplay_instance, ttl);
    add_srv_record(packet, raop_instance, host_name, port, ttl);
    add_txt_record(packet, raop_instance, raop_txt_items, ttl);
    add_srv_record(packet, airplay_instance, host_name, port, ttl);
    add_txt_record(packet, airplay_instance, airplay_txt_items, ttl);
    for (uint32_t ip : ips) {
        add_a_record(packet, host_name, ip, ttl);
    }
    return packet;
}

bool query_matches(const uint8_t* data,
                   size_t size,
                   const std::string& raop_instance,
                   const std::string& airplay_instance,
                   const std::string& host_name) {
    if (size < 12) {
        return false;
    }
    const uint16_t qdcount = static_cast<uint16_t>((data[4] << 8) | data[5]);
    size_t offset = 12;
    const std::string raop_type_l = to_lower_ascii(kRaopServiceType);
    const std::string airplay_type_l = to_lower_ascii(kAirPlayServiceType);
    const std::string raop_instance_l = to_lower_ascii(raop_instance);
    const std::string airplay_instance_l = to_lower_ascii(airplay_instance);
    const std::string host_l = to_lower_ascii(host_name);

    for (uint16_t i = 0; i < qdcount; ++i) {
        std::string qname;
        if (!read_name(data, size, offset, qname) || offset + 4 > size) {
            return false;
        }
        const uint16_t qtype =
            static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        offset += 4;

        qname = to_lower_ascii(qname);
        if ((qname == raop_type_l && (qtype == 12 || qtype == 255)) ||
            (qname == airplay_type_l && (qtype == 12 || qtype == 255)) ||
            (qname == raop_instance_l && (qtype == 16 || qtype == 33 || qtype == 255)) ||
            (qname == airplay_instance_l && (qtype == 16 || qtype == 33 || qtype == 255)) ||
            (qname == host_l && (qtype == 1 || qtype == 255))) {
            return true;
        }
    }
    return false;
}

void send_multicast(SOCKET s, const std::vector<uint8_t>& packet) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(kMdnsPort);
    InetPtonA(AF_INET, kMulticastAddr, &dst.sin_addr);
    sendto(s,
           reinterpret_cast<const char*>(packet.data()),
           static_cast<int>(packet.size()),
           0,
           reinterpret_cast<sockaddr*>(&dst),
           sizeof(dst));
}

std::vector<std::string> narrow_txt(const std::vector<std::wstring>& txt) {
    std::vector<std::string> out;
    out.reserve(txt.size());
    for (const auto& item : txt) {
        out.push_back(narrow_ascii(item));
    }
    return out;
}

} // namespace

class UdpMdnsAdvertiser {
public:
    UdpMdnsAdvertiser() = default;
    ~UdpMdnsAdvertiser() { stop(); }

    bool start(const std::string& raop_instance,
               const std::string& airplay_instance,
               const std::string& advertise_ipv4,
               const std::vector<std::wstring>& raop_txt,
               const std::vector<std::wstring>& airplay_txt,
               uint16_t port,
               std::string& error) {
        stop();

        raop_instance_ = raop_instance;
        airplay_instance_ = airplay_instance;
        host_name_ = local_host_name_ascii();
        port_ = port;
        raop_txt_ = narrow_txt(raop_txt);
        airplay_txt_ = narrow_txt(airplay_txt);
        ipv4_.clear();

        if (!advertise_ipv4.empty()) {
            IN_ADDR addr{};
            if (InetPtonA(AF_INET, advertise_ipv4.c_str(), &addr) != 1) {
                error = "invalid advertise_ipv4: " + advertise_ipv4;
                return false;
            }
            ipv4_.push_back(addr.S_un.S_addr);
        } else {
            ipv4_ = local_ipv4_addresses();
        }

        udp_tx_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_tx_ == INVALID_SOCKET) {
            error = "UDP mDNS transmit socket failed: " +
                    std::to_string(WSAGetLastError());
            return false;
        }

        DWORD ttl = 255;
        setsockopt(udp_tx_,
                   IPPROTO_IP,
                   IP_MULTICAST_TTL,
                   reinterpret_cast<const char*>(&ttl),
                   sizeof(ttl));
        BOOL loop = TRUE;
        setsockopt(udp_tx_,
                   IPPROTO_IP,
                   IP_MULTICAST_LOOP,
                   reinterpret_cast<const char*>(&loop),
                   sizeof(loop));
        if (!ipv4_.empty()) {
            IN_ADDR iface{};
            iface.S_un.S_addr = ipv4_.front();
            setsockopt(udp_tx_,
                       IPPROTO_IP,
                       IP_MULTICAST_IF,
                       reinterpret_cast<const char*>(&iface),
                       sizeof(iface));
        }

        udp_rx_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_rx_ != INVALID_SOCKET) {
            BOOL yes = TRUE;
            setsockopt(udp_rx_,
                       SOL_SOCKET,
                       SO_REUSEADDR,
                       reinterpret_cast<const char*>(&yes),
                       sizeof(yes));
            sockaddr_in bind_addr{};
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_port = htons(kMdnsPort);
            bind_addr.sin_addr.s_addr = INADDR_ANY;
            if (bind(udp_rx_,
                     reinterpret_cast<sockaddr*>(&bind_addr),
                     sizeof(bind_addr)) == SOCKET_ERROR) {
                closesocket(udp_rx_);
                udp_rx_ = INVALID_SOCKET;
            } else {
                ip_mreq mreq{};
                InetPtonA(AF_INET, kMulticastAddr, &mreq.imr_multiaddr);
                mreq.imr_interface.s_addr =
                    ipv4_.empty() ? INADDR_ANY : ipv4_.front();
                setsockopt(udp_rx_,
                           IPPROTO_IP,
                           IP_ADD_MEMBERSHIP,
                           reinterpret_cast<const char*>(&mreq),
                           sizeof(mreq));
            }
        }

        running_.store(true, std::memory_order_release);
        worker_ = std::thread(&UdpMdnsAdvertiser::loop, this);
        std::fprintf(stderr,
                     "[airplay-mdns] UDP fallback active for '%s' / '%s' on port %u (%zu IPv4 records)\n",
                     raop_instance_.c_str(),
                     airplay_instance_.c_str(),
                     static_cast<unsigned>(port_),
                     ipv4_.size());
        return true;
    }

    void stop() {
        const bool was_running = running_.exchange(false, std::memory_order_acq_rel);
        if (udp_rx_ != INVALID_SOCKET) {
            closesocket(udp_rx_);
            udp_rx_ = INVALID_SOCKET;
        }
        if (worker_.joinable()) {
            worker_.join();
        }
        if (was_running && udp_tx_ != INVALID_SOCKET) {
            auto goodbye = build_response_packet(raop_instance_,
                                                 airplay_instance_,
                                                 host_name_,
                                                 port_,
                                                 raop_txt_,
                                                 airplay_txt_,
                                                 ipv4_,
                                                 0);
            send_multicast(udp_tx_, goodbye);
        }
        if (udp_tx_ != INVALID_SOCKET) {
            closesocket(udp_tx_);
            udp_tx_ = INVALID_SOCKET;
        }
    }

    bool is_running() const {
        return running_.load(std::memory_order_acquire);
    }

private:
    void loop() {
        using clock = std::chrono::steady_clock;
        auto packet = build_response_packet(raop_instance_,
                                            airplay_instance_,
                                            host_name_,
                                            port_,
                                            raop_txt_,
                                            airplay_txt_,
                                            ipv4_,
                                            kRecordTtlSeconds);
        auto next_announce = clock::now();
        int fast_announces = 3;

        while (running_.load(std::memory_order_acquire)) {
            if (clock::now() >= next_announce) {
                send_multicast(udp_tx_, packet);
                if (fast_announces > 0) {
                    --fast_announces;
                    next_announce = clock::now() + std::chrono::seconds(1);
                } else {
                    next_announce = clock::now() + std::chrono::seconds(30);
                }
            }

            if (udp_rx_ == INVALID_SOCKET) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(udp_rx_, &readfds);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 250000;
            const int ready = select(0, &readfds, nullptr, nullptr, &tv);
            if (ready <= 0 || !FD_ISSET(udp_rx_, &readfds)) {
                continue;
            }

            uint8_t buf[1500];
            sockaddr_in from{};
            int from_len = sizeof(from);
            const int received = recvfrom(udp_rx_,
                                          reinterpret_cast<char*>(buf),
                                          sizeof(buf),
                                          0,
                                          reinterpret_cast<sockaddr*>(&from),
                                          &from_len);
            if (received > 0 &&
                query_matches(buf,
                              static_cast<size_t>(received),
                              raop_instance_,
                              airplay_instance_,
                              host_name_)) {
                send_multicast(udp_tx_, packet);
            }
        }
    }

    std::atomic<bool> running_{false};
    std::thread worker_;
    SOCKET udp_tx_ = INVALID_SOCKET;
    SOCKET udp_rx_ = INVALID_SOCKET;
    std::string raop_instance_;
    std::string airplay_instance_;
    std::string host_name_;
    uint16_t port_ = 0;
    std::vector<std::string> raop_txt_;
    std::vector<std::string> airplay_txt_;
    std::vector<uint32_t> ipv4_;
};

DnssdAdvertiser::DnssdAdvertiser() = default;

DnssdAdvertiser::~DnssdAdvertiser() {
    stop();
}

bool DnssdAdvertiser::start(const std::string& device_name,
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
                            std::string& error) {
    stop();

    const std::wstring name = utils::widen(device_name);
    const std::wstring id = utils::widen(device_id);
    const std::wstring raop_instance = id + L"@" + name + L"._raop._tcp.local";
    const std::wstring airplay_instance = name + L"._airplay._tcp.local";
    const std::string raop_instance_udp =
        device_id + "@" + device_name + "." + kRaopServiceType;
    const std::string airplay_instance_udp =
        device_name + "." + kAirPlayServiceType;
    const auto raop_txt_items = raop_txt(model,
                                        source_version,
                                        firmware_version,
                                        feature_flags,
                                        raop_codecs,
                                        raop_encryption_types);
    const auto airplay_txt_items = airplay_txt(device_id,
                                               manufacturer,
                                               model,
                                               source_version,
                                               firmware_version,
                                               feature_flags);

    auto start_udp_fallback = [&]() {
        if (!udp_mdns_) {
            udp_mdns_ = std::make_unique<UdpMdnsAdvertiser>();
        }
        std::string udp_error;
        if (udp_mdns_->start(raop_instance_udp,
                             airplay_instance_udp,
                             advertise_ipv4,
                             raop_txt_items,
                             airplay_txt_items,
                             rtsp_port,
                             udp_error)) {
            running_ = true;
            return true;
        }
        error = udp_error;
        return false;
    };

    if (running_under_wine()) {
        std::fprintf(stderr,
                     "[airplay-mdns] Wine detected; using UDP mDNS fallback\n");
        return start_udp_fallback();
    }

    if (!register_service(raop_instance,
                          rtsp_port,
                          advertise_ipv4,
                          raop_txt_items,
                          error)) {
        const std::string dns_error = error;
        stop();
        std::fprintf(stderr,
                     "[airplay-mdns] Windows DNS-SD RAOP registration failed (%s); trying UDP fallback\n",
                     dns_error.c_str());
        if (start_udp_fallback()) {
            error.clear();
            return true;
        }
        error = dns_error + "; UDP mDNS fallback failed: " + error;
        return false;
    }
    if (!register_service(airplay_instance,
                          rtsp_port,
                          advertise_ipv4,
                          airplay_txt_items,
                          error)) {
        const std::string dns_error = error;
        stop();
        std::fprintf(stderr,
                     "[airplay-mdns] Windows DNS-SD AirPlay registration failed (%s); trying UDP fallback\n",
                     dns_error.c_str());
        if (start_udp_fallback()) {
            error.clear();
            return true;
        }
        error = dns_error + "; UDP mDNS fallback failed: " + error;
        return false;
    }

    running_ = true;
    return true;
}

void DnssdAdvertiser::stop() {
    if (udp_mdns_) {
        udp_mdns_->stop();
    }
    deregister_service(raop_cancel_, raop_instance_);
    deregister_service(airplay_cancel_, airplay_instance_);
    running_ = false;
}

bool DnssdAdvertiser::is_running() const {
    return running_;
}

bool DnssdAdvertiser::register_service(const std::wstring& instance,
                                       uint16_t port,
                                       const std::string& advertise_ipv4,
                                       const std::vector<std::wstring>& txt,
                                       std::string& error) {
    const DnsApi& api = dns_api();
    if (!api.construct_instance || !api.register_service ||
        !api.deregister_service || !api.free_instance) {
        error = "Windows DNS-SD unavailable";
        return false;
    }

    auto cancel = new DNS_SERVICE_CANCEL{};

    std::vector<std::wstring> keys;
    std::vector<std::wstring> values;
    keys.reserve(txt.size());
    values.reserve(txt.size());
    for (const auto& item : txt) {
        const size_t equals = item.find(L'=');
        if (equals == std::wstring::npos) {
            keys.push_back(item);
            values.emplace_back();
        } else {
            keys.push_back(item.substr(0, equals));
            values.push_back(item.substr(equals + 1));
        }
    }

    std::vector<PCWSTR> key_ptrs;
    std::vector<PCWSTR> value_ptrs;
    key_ptrs.reserve(keys.size());
    value_ptrs.reserve(values.size());
    for (size_t i = 0; i < keys.size(); ++i) {
        key_ptrs.push_back(keys[i].c_str());
        value_ptrs.push_back(values[i].c_str());
    }

    const std::wstring host = local_host_name();
    IP4_ADDRESS ip4{};
    IP4_ADDRESS* ip4_ptr = nullptr;
    if (!advertise_ipv4.empty()) {
        IN_ADDR addr{};
        if (InetPtonA(AF_INET, advertise_ipv4.c_str(), &addr) != 1) {
            error = "invalid advertise_ipv4: " + advertise_ipv4;
            delete cancel;
            return false;
        }
        ip4 = addr.S_un.S_addr;
        ip4_ptr = &ip4;
    }
    PDNS_SERVICE_INSTANCE instance_data = api.construct_instance(
        instance.c_str(),
        host.c_str(),
        ip4_ptr,
        nullptr,
        port,
        0,
        0,
        static_cast<DWORD>(key_ptrs.size()),
        key_ptrs.empty() ? nullptr : key_ptrs.data(),
        value_ptrs.empty() ? nullptr : value_ptrs.data());

    if (!instance_data) {
        error = "DnsServiceConstructInstance failed";
        delete cancel;
        return false;
    }

    DNS_SERVICE_REGISTER_REQUEST request{};
    request.Version = DNS_QUERY_REQUEST_VERSION1;
    request.InterfaceIndex = 0;
    request.pServiceInstance = instance_data;
    request.pRegisterCompletionCallback = register_complete;
    request.pQueryContext = const_cast<DnsApi*>(&api);
    request.hCredentials = nullptr;
    request.unicastEnabled = FALSE;

    const DNS_STATUS status = api.register_service(&request, cancel);
    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS) {
        error = win32_error("DnsServiceRegister", status);
        api.free_instance(instance_data);
        delete cancel;
        return false;
    }

    if (instance.find(L"_raop") != std::wstring::npos) {
        raop_cancel_ = cancel;
        raop_instance_ = instance_data;
    } else {
        airplay_cancel_ = cancel;
        airplay_instance_ = instance_data;
    }
    return true;
}

} // namespace airplayc::discovery
