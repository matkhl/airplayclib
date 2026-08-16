#include "dacp_client.h"

#include "../utils/string_utils.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <map>
#include <mutex>
#include <sstream>
#include <string_view>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>

namespace airplayc::net {
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

std::string wsa_error(const char* action) {
    std::ostringstream out;
    out << action << " failed with WSA error " << WSAGetLastError();
    return out.str();
}

void write_u16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

std::vector<uint8_t> encode_dns_name(std::string name) {
    if (!name.empty() && name.back() == '.') {
        name.pop_back();
    }
    std::vector<uint8_t> out;
    size_t start = 0;
    while (start < name.size()) {
        const size_t dot = name.find('.', start);
        const size_t end = dot == std::string::npos ? name.size() : dot;
        const size_t len = end - start;
        out.push_back(static_cast<uint8_t>(len));
        out.insert(out.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                   name.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    out.push_back(0);
    return out;
}

std::vector<uint8_t> build_query(const std::string& name) {
    std::vector<uint8_t> out;
    write_u16(out, 0);
    write_u16(out, 0);
    write_u16(out, 1);
    write_u16(out, 0);
    write_u16(out, 0);
    write_u16(out, 0);
    const auto qname = encode_dns_name(name);
    out.insert(out.end(), qname.begin(), qname.end());
    write_u16(out, 12);
    write_u16(out, 0x8001);
    return out;
}

bool read_u16(const std::vector<uint8_t>& data, size_t& offset, uint16_t& value) {
    if (offset + 2 > data.size()) {
        return false;
    }
    value = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    return true;
}

bool read_u32(const std::vector<uint8_t>& data, size_t& offset, uint32_t& value) {
    if (offset + 4 > data.size()) {
        return false;
    }
    value = (static_cast<uint32_t>(data[offset]) << 24) |
            (static_cast<uint32_t>(data[offset + 1]) << 16) |
            (static_cast<uint32_t>(data[offset + 2]) << 8) |
            static_cast<uint32_t>(data[offset + 3]);
    offset += 4;
    return true;
}

bool read_name_at(const std::vector<uint8_t>& data, size_t& offset, std::string& name) {
    std::vector<std::string> labels;
    size_t pos = offset;
    bool jumped = false;
    for (size_t guard = 0; guard < 128; ++guard) {
        if (pos >= data.size()) {
            return false;
        }
        const uint8_t len = data[pos];
        if (len == 0) {
            ++pos;
            if (!jumped) {
                offset = pos;
            }
            name.clear();
            for (size_t i = 0; i < labels.size(); ++i) {
                if (i != 0) {
                    name.push_back('.');
                }
                name += labels[i];
            }
            return true;
        }
        if ((len & 0xc0) == 0xc0) {
            if (pos + 1 >= data.size()) {
                return false;
            }
            const size_t ptr = ((len & 0x3f) << 8) | data[pos + 1];
            if (!jumped) {
                offset = pos + 2;
            }
            pos = ptr;
            jumped = true;
            continue;
        }
        ++pos;
        if (pos + len > data.size()) {
            return false;
        }
        labels.emplace_back(reinterpret_cast<const char*>(data.data() + pos), len);
        pos += len;
    }
    return false;
}

struct MdnsRecords {
    std::vector<std::string> ptrs;
    std::map<std::string, std::pair<std::string, uint16_t>> srv_by_name;
    std::map<std::string, std::string> a_by_name;
};

void parse_mdns_packet(const std::vector<uint8_t>& data, MdnsRecords& records) {
    if (data.size() < 12) {
        return;
    }
    size_t offset = 4;
    uint16_t qd = 0;
    uint16_t an = 0;
    uint16_t ns = 0;
    uint16_t ar = 0;
    if (!read_u16(data, offset, qd) ||
        !read_u16(data, offset, an) ||
        !read_u16(data, offset, ns) ||
        !read_u16(data, offset, ar)) {
        return;
    }

    for (uint16_t i = 0; i < qd; ++i) {
        std::string ignored;
        if (!read_name_at(data, offset, ignored) || offset + 4 > data.size()) {
            return;
        }
        offset += 4;
    }

    const uint16_t count = static_cast<uint16_t>(an + ns + ar);
    for (uint16_t i = 0; i < count; ++i) {
        std::string name;
        uint16_t type = 0;
        uint16_t klass = 0;
        uint32_t ttl = 0;
        uint16_t rdlen = 0;
        if (!read_name_at(data, offset, name) ||
            !read_u16(data, offset, type) ||
            !read_u16(data, offset, klass) ||
            !read_u32(data, offset, ttl) ||
            !read_u16(data, offset, rdlen) ||
            offset + rdlen > data.size()) {
            return;
        }
        (void)klass;
        (void)ttl;
        const size_t rstart = offset;
        if (type == 12) {
            size_t rpos = rstart;
            std::string ptr;
            if (read_name_at(data, rpos, ptr)) {
                records.ptrs.push_back(ptr);
            }
        } else if (type == 33 && rdlen >= 6) {
            size_t rpos = rstart + 4;
            uint16_t port = 0;
            std::string target;
            if (read_u16(data, rpos, port) && read_name_at(data, rpos, target)) {
                records.srv_by_name[name] = {target, port};
            }
        } else if (type == 1 && rdlen == 4) {
            std::ostringstream ip;
            ip << static_cast<unsigned>(data[rstart]) << '.'
               << static_cast<unsigned>(data[rstart + 1]) << '.'
               << static_cast<unsigned>(data[rstart + 2]) << '.'
               << static_cast<unsigned>(data[rstart + 3]);
            records.a_by_name[name] = ip.str();
        }
        offset = rstart + rdlen;
    }
}

bool contains_id(std::string value, std::string id) {
    value = utils::to_lower(value);
    id = utils::to_lower(id);
    id.erase(std::remove(id.begin(), id.end(), ':'), id.end());
    id.erase(std::remove(id.begin(), id.end(), '-'), id.end());
    std::string compact = value;
    compact.erase(std::remove(compact.begin(), compact.end(), ':'), compact.end());
    compact.erase(std::remove(compact.begin(), compact.end(), '-'), compact.end());
    return !id.empty() && compact.find(id) != std::string::npos;
}

struct DacpTarget {
    std::string host;
    uint16_t port = 0;
};

std::mutex g_dacp_cache_mutex;
std::map<std::string, DacpTarget> g_dacp_cache;

std::string cache_key(const DacpRemoteInfo& remote) {
    return remote.dacp_id + "|" + remote.active_remote + "|" +
           remote.fallback_host;
}

bool target_from_records(const MdnsRecords& records,
                         const std::string& dacp_id,
                         DacpTarget& target) {
    for (const auto& service : records.ptrs) {
        if (!contains_id(service, dacp_id)) {
            continue;
        }
        const auto srv = records.srv_by_name.find(service);
        if (srv == records.srv_by_name.end()) {
            continue;
        }
        target.host = srv->second.first;
        target.port = srv->second.second;
        const auto a = records.a_by_name.find(target.host);
        if (a != records.a_by_name.end()) {
            target.host = a->second;
        }
        return !target.host.empty() && target.port != 0;
    }
    return false;
}

bool discover_dacp_target(const std::string& dacp_id,
                          const std::string& fallback_host,
                          const std::string& local_query_address,
                          DacpTarget& target) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    DWORD timeout = 250;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    if (!local_query_address.empty()) {
        in_addr local_if{};
        if (inet_pton(AF_INET, local_query_address.c_str(), &local_if) == 1) {
            sockaddr_in local{};
            local.sin_family = AF_INET;
            local.sin_port = 0;
            local.sin_addr = local_if;
            bind(sock, reinterpret_cast<sockaddr*>(&local), sizeof(local));
            setsockopt(sock,
                       IPPROTO_IP,
                       IP_MULTICAST_IF,
                       reinterpret_cast<const char*>(&local_if),
                       sizeof(local_if));
        }
    }

    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(5353);
    inet_pton(AF_INET, "224.0.0.251", &remote.sin_addr);

    const auto query = build_query("_dacp._tcp.local");
    sendto(sock,
           reinterpret_cast<const char*>(query.data()),
           static_cast<int>(query.size()),
           0,
           reinterpret_cast<sockaddr*>(&remote),
           sizeof(remote));

    MdnsRecords records;
    const auto stop = std::chrono::steady_clock::now() + std::chrono::milliseconds(600);
    while (std::chrono::steady_clock::now() < stop) {
        std::array<uint8_t, 2048> buffer{};
        sockaddr_in from{};
        int from_len = sizeof(from);
        const int received = recvfrom(sock,
                                      reinterpret_cast<char*>(buffer.data()),
                                      static_cast<int>(buffer.size()),
                                      0,
                                      reinterpret_cast<sockaddr*>(&from),
                                      &from_len);
        if (received <= 0) {
            continue;
        }
        parse_mdns_packet(std::vector<uint8_t>(buffer.begin(), buffer.begin() + received), records);
        if (target_from_records(records, dacp_id, target)) {
            closesocket(sock);
            return true;
        }
    }
    closesocket(sock);

    if (target_from_records(records, dacp_id, target)) {
        return true;
    }
    if (!fallback_host.empty()) {
        target.host = fallback_host;
        target.port = 3689;
        return true;
    }
    return false;
}

bool connect_one_with_timeout(SOCKET sock, const sockaddr* addr, int addr_len, std::string& error) {
    u_long nonblocking = 1;
    ioctlsocket(sock, FIONBIO, &nonblocking);
    const int rc = connect(sock, addr, addr_len);
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        error = wsa_error("DACP connect");
        return false;
    }

    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(sock, &write_set);
    timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 600000;
    const int selected = select(0, nullptr, &write_set, nullptr, &tv);
    if (selected <= 0) {
        error = "DACP connect timed out";
        return false;
    }

    int socket_error = 0;
    int socket_error_len = sizeof(socket_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&socket_error), &socket_error_len);
    if (socket_error != 0) {
        std::ostringstream out;
        out << "DACP connect failed with WSA error " << socket_error;
        error = out.str();
        return false;
    }

    nonblocking = 0;
    ioctlsocket(sock, FIONBIO, &nonblocking);
    return true;
}

bool connect_with_timeout(SOCKET& sock, const std::string& host, uint16_t port, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    const std::string port_text = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_text.c_str(), &hints, &result) != 0 || result == nullptr) {
        error = "failed to resolve DACP target: " + host;
        return false;
    }

    std::string last_error;
    for (addrinfo* item = result; item != nullptr; item = item->ai_next) {
        SOCKET candidate = socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (candidate == INVALID_SOCKET) {
            last_error = wsa_error("DACP socket");
            continue;
        }
        DWORD timeout = 750;
        setsockopt(candidate, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(candidate, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        if (connect_one_with_timeout(candidate, item->ai_addr, static_cast<int>(item->ai_addrlen), last_error)) {
            freeaddrinfo(result);
            sock = candidate;
            return true;
        }
        closesocket(candidate);
    }
    freeaddrinfo(result);
    error = last_error.empty() ? "DACP connect failed" : last_error;
    return false;
}

bool send_all(SOCKET sock, const std::string& data, std::string& error) {
    size_t sent = 0;
    while (sent < data.size()) {
        const int rc = send(sock,
                            data.data() + sent,
                            static_cast<int>(data.size() - sent),
                            0);
        if (rc <= 0) {
            error = wsa_error("DACP send");
            return false;
        }
        sent += static_cast<size_t>(rc);
    }
    return true;
}

bool read_http_status(SOCKET sock, int& status) {
    std::string data;
    std::array<char, 512> buffer{};
    const int received = recv(sock, buffer.data(), static_cast<int>(buffer.size()), 0);
    if (received <= 0) {
        return false;
    }
    data.assign(buffer.data(), static_cast<size_t>(received));
    const size_t first_space = data.find(' ');
    if (first_space == std::string::npos || first_space + 4 > data.size()) {
        return false;
    }
    status = std::atoi(data.c_str() + first_space + 1);
    return status >= 100;
}

}

bool send_dacp_command(const DacpRemoteInfo& remote,
                       const std::string& command,
                       std::string& error) {
    static WsaRuntime wsa;
    if (!wsa.ok()) {
        error = "WSAStartup failed";
        return false;
    }
    if (remote.active_remote.empty()) {
        error = "AirPlay client did not provide Active-Remote";
        return false;
    }

    DacpTarget target;
    const auto key = cache_key(remote);
    {
        std::lock_guard lock(g_dacp_cache_mutex);
        const auto cached = g_dacp_cache.find(key);
        if (cached != g_dacp_cache.end()) {
            target = cached->second;
        }
    }
    if (target.host.empty() || target.port == 0) {
        if (!discover_dacp_target(remote.dacp_id,
                                  remote.fallback_host,
                                  remote.local_query_address,
                                  target)) {
            error = "DACP target was not found";
            return false;
        }
    }

    SOCKET sock = INVALID_SOCKET;
    if (!connect_with_timeout(sock, target.host, target.port, error)) {
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
        {
            std::lock_guard lock(g_dacp_cache_mutex);
            g_dacp_cache.erase(key);
        }
        return false;
    }

    std::ostringstream request;
    request << "GET /ctrl-int/1/" << command << " HTTP/1.1\r\n"
            << "Host: " << target.host << ':' << target.port << "\r\n"
            << "Active-Remote: " << remote.active_remote << "\r\n"
            << "Connection: close\r\n\r\n";

    if (!send_all(sock, request.str(), error)) {
        closesocket(sock);
        return false;
    }

    int status = 0;
    if (!read_http_status(sock, status)) {
        closesocket(sock);
        error = "DACP response did not contain a valid HTTP status";
        return false;
    }
    closesocket(sock);

    if (status < 200 || status >= 300) {
        std::ostringstream out;
        out << "DACP command failed with HTTP status " << status;
        error = out.str();
        return false;
    }
    {
        std::lock_guard lock(g_dacp_cache_mutex);
        g_dacp_cache[key] = target;
    }
    return true;
}

}
