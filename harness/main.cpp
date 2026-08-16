#include <airplayc/airplayc.h>
#include "../src/crypto/fairplay.h"

#include <atomic>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void print_usage() {
    std::cout << "Usage: harness [--self-test] [--name NAME] [--advertise-ip IPV4] [--port PORT]\n"
                 "Starts an AirPlay audio receiver and waits for Enter.\n";
}

} // namespace

int main(int argc, char** argv) {
    airplayc::Config config;
    bool self_test = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help") {
            print_usage();
            return 0;
        }
        if (arg == "--self-test") {
            self_test = true;
            continue;
        }
        if ((arg == "--name" || arg == "--advertise-ip" || arg == "--port") && i + 1 < argc) {
            const std::string value = argv[++i];
            if (arg == "--name") {
                config.device_name = value;
            } else if (arg == "--advertise-ip") {
                config.advertise_ipv4 = value;
            } else {
                try {
                    const auto port = std::stoul(value);
                    if (port > 65535) {
                        throw std::out_of_range("port");
                    }
                    config.rtsp_port = static_cast<uint16_t>(port);
                } catch (...) {
                    print_usage();
                    return 2;
                }
            }
            continue;
        }
        print_usage();
        return 2;
    }

    if (self_test) {
        std::string error;
        if (!airplayc::crypto::fairplay_self_test(error)) {
            std::cerr << "FairPlay self-test failed: " << error << '\n';
            return 1;
        }
        std::cout << "FairPlay self-test passed.\n";
        return 0;
    }

    std::atomic<uint64_t> frames_received{0};
    config.on_audio = [&frames_received](const int16_t*, size_t frames,
                                         const airplayc::AudioFormat&) {
        frames_received.fetch_add(frames, std::memory_order_relaxed);
        return true;
    };
    config.on_metadata = [](const airplayc::Metadata& metadata) {
        std::cout << "Now playing: " << metadata.artist << " - " << metadata.title << '\n';
    };
    config.on_event = [](const airplayc::Event& event) {
        if (!event.detail.empty()) {
            std::cout << "Event: " << event.detail << '\n';
        }
    };

    auto session = airplayc::Session::create(config);
    if (!session || !session->start()) {
        std::cerr << "Start failed";
        if (session && !session->last_error_message().empty()) {
            std::cerr << ": " << session->last_error_message();
        }
        std::cerr << '\n';
        return 1;
    }

    std::cout << "Receiver is available as '" << config.device_name
              << "' on RTSP port " << session->rtsp_port()
              << ". Press Enter to stop.\n";
    std::string line;
    std::getline(std::cin, line);
    session->stop();
    std::cout << "Received " << frames_received.load() << " PCM frames.\n";
    return 0;
}
