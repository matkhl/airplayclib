#pragma once

#include "../../include/airplayc/airplayc.h"

#include <atomic>
#include <thread>

namespace airplayc::audio {

class SilencePipeline {
public:
    explicit SilencePipeline(AudioCallback callback);
    ~SilencePipeline();

    void start();
    void stop();

private:
    void run();

    AudioCallback callback_;
    std::thread thread_;
    std::atomic<bool> running_{false};
};

} // namespace airplayc::audio
