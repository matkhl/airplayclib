#pragma once

#include <cstdint>
#include <string>

namespace airplayc::net {

struct DacpRemoteInfo {
    std::string dacp_id;
    std::string active_remote;
    std::string fallback_host;
    std::string local_query_address;
};

bool send_dacp_command(const DacpRemoteInfo& remote,
                       const std::string& command,
                       std::string& error);

}
