#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace airplayc::rtsp {

struct Request {
    std::string method;
    std::string uri;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;

    std::string header(const std::string& name) const;
    uint32_t cseq() const;
};

struct Response {
    std::string version = "RTSP/1.0";
    int status = 200;
    std::string reason = "OK";
    std::map<std::string, std::string> headers;
    std::string body;

    std::string serialize() const;
};

bool try_parse_request(const std::string& buffer, Request& request, size_t& consumed);
Response make_response(const Request& request, int status = 200, std::string reason = "OK");

} // namespace airplayc::rtsp
