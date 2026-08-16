#include "audio_pipeline.h"

#include <array>
#include <chrono>
#include <thread>

namespace airplayc::audio {

SilencePipeline::SilencePipeline(AudioCallback callback)
    : callback_(std::move(callback)) {}

SilencePipeline::~SilencePipeline() {
    stop();
}

void SilencePipeline::start() {
    if (running_.exchange(true)) {
        return;
    }
    thread_ = std::thread([this] { run(); });
}

void SilencePipeline::stop() {
    running_.store(false);
    if (thread_.joinable()) {
        thread_.join();
    }
}

void SilencePipeline::run() {
    if (!callback_) {
        return;
    }
    AudioFormat format;
    constexpr size_t frames = 441;
    std::array<int16_t, frames * 2> silence{};
    while (running_.load()) {
        if (!callback_(silence.data(), frames, format)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

} // namespace airplayc::audio
