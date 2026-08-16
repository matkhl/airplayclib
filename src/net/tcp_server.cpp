#include "tcp_server.h"

#include <algorithm>
#include <sstream>

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

} // namespace

TcpServer::TcpServer() = default;

TcpServer::~TcpServer() {
    stop();
}

bool TcpServer::start(uint16_t port, ClientHandler handler, std::string& error) {
    stop();

    static WsaRuntime wsa;
    if (!wsa.ok()) {
        error = "WSAStartup failed";
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        error = wsa_error("socket");
        return false;
    }

    BOOL reuse = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        error = wsa_error("bind");
        closesocket(sock);
        return false;
    }

    if (listen(sock, SOMAXCONN) == SOCKET_ERROR) {
        error = wsa_error("listen");
        closesocket(sock);
        return false;
    }

    sockaddr_in actual{};
    int actual_len = sizeof(actual);
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&actual), &actual_len) == SOCKET_ERROR) {
        error = wsa_error("getsockname");
        closesocket(sock);
        return false;
    }

    listen_socket_ = static_cast<uintptr_t>(sock);
    port_ = ntohs(actual.sin_port);
    handler_ = std::move(handler);
    running_.store(true);
    thread_ = std::thread([this] { accept_loop(); });
    return true;
}

void TcpServer::stop() {
    running_.store(false);
    if (listen_socket_ != static_cast<uintptr_t>(~0ull)) {
        shutdown(static_cast<SOCKET>(listen_socket_), SD_BOTH);
        closesocket(static_cast<SOCKET>(listen_socket_));
        listen_socket_ = static_cast<uintptr_t>(~0ull);
    }
    {
        std::lock_guard lock(client_mutex_);
        for (uintptr_t client : client_sockets_) {
            shutdown(static_cast<SOCKET>(client), SD_BOTH);
        }
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    std::vector<std::thread> clients;
    {
        std::lock_guard lock(client_mutex_);
        clients.swap(client_threads_);
    }
    for (auto& client : clients) {
        if (client.joinable()) {
            client.join();
        }
    }
    port_ = 0;
}

bool TcpServer::is_running() const {
    return running_.load();
}

uint16_t TcpServer::port() const {
    return port_;
}

void TcpServer::accept_loop() {
    while (running_.load()) {
        sockaddr_storage remote_addr{};
        int remote_len = sizeof(remote_addr);
        SOCKET client = accept(static_cast<SOCKET>(listen_socket_), reinterpret_cast<sockaddr*>(&remote_addr), &remote_len);
        if (client == INVALID_SOCKET) {
            if (running_.load()) {
                continue;
            }
            break;
        }

        char host[NI_MAXHOST]{};
        getnameinfo(reinterpret_cast<sockaddr*>(&remote_addr), remote_len, host, sizeof(host), nullptr, 0, NI_NUMERICHOST);
        auto handler = handler_;
        {
            std::lock_guard lock(client_mutex_);
            client_sockets_.push_back(static_cast<uintptr_t>(client));
            client_threads_.emplace_back([this, handler, client,
                                          remote = std::string(host)] {
            if (handler) {
                handler(static_cast<uintptr_t>(client), remote);
            }
            shutdown(client, SD_BOTH);
            closesocket(client);
            {
                std::lock_guard lock(client_mutex_);
                auto value = static_cast<uintptr_t>(client);
                client_sockets_.erase(
                    std::remove(client_sockets_.begin(),
                                client_sockets_.end(),
                                value),
                    client_sockets_.end());
            }
            });
        }
    }
}

} // namespace airplayc::net
