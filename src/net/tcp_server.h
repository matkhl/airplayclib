#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace airplayc::net {

class TcpServer {
public:
    using ClientHandler = std::function<void(uintptr_t socket_handle, const std::string& remote)>;

    TcpServer();
    ~TcpServer();

    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;

    bool start(uint16_t port, ClientHandler handler, std::string& error);
    void stop();
    bool is_running() const;
    uint16_t port() const;

private:
    void accept_loop();

    uintptr_t listen_socket_ = static_cast<uintptr_t>(~0ull);
    uint16_t port_ = 0;
    ClientHandler handler_;
    std::thread thread_;
    std::mutex client_mutex_;
    std::vector<std::thread> client_threads_;
    std::vector<uintptr_t> client_sockets_;
    std::atomic<bool> running_{false};
};

} // namespace airplayc::net
