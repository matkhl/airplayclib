#include "rtsp_message.h"

#include "../utils/string_utils.h"

#include <charconv>
#include <sstream>

namespace airplayc::rtsp {

std::string Request::header(const std::string& name) const {
    const auto found = headers.find(utils::to_lower(name));
    return found == headers.end() ? std::string{} : found->second;
}

uint32_t Request::cseq() const {
    const auto value = header("CSeq");
    uint32_t parsed = 0;
    std::from_chars(value.data(), value.data() + value.size(), parsed);
    return parsed;
}

std::string Response::serialize() const {
    std::ostringstream out;
    out << version << ' ' << status << ' ' << reason << "\r\n";
    for (const auto& [name, value] : headers) {
        out << name << ": " << value << "\r\n";
    }
    out << "Content-Length: " << body.size() << "\r\n";
    out << "\r\n";
    out << body;
    return out.str();
}

bool try_parse_request(const std::string& buffer, Request& request, size_t& consumed) {
    consumed = 0;
    const size_t header_end = buffer.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        return false;
    }

    const std::string header_block = buffer.substr(0, header_end);
    auto lines = utils::split_lines(header_block);
    if (lines.empty()) {
        return false;
    }

    std::istringstream start_line(lines.front());
    Request parsed;
    start_line >> parsed.method >> parsed.uri >> parsed.version;
    if (parsed.method.empty() || parsed.version.empty()) {
        consumed = header_end + 4;
        return false;
    }

    size_t content_length = 0;
    for (size_t i = 1; i < lines.size(); ++i) {
        const size_t colon = lines[i].find(':');
        if (colon == std::string::npos) {
            continue;
        }
        const auto name = utils::to_lower(utils::trim(lines[i].substr(0, colon)));
        const auto value = utils::trim(lines[i].substr(colon + 1));
        parsed.headers[name] = value;
        if (name == "content-length") {
            std::from_chars(value.data(), value.data() + value.size(), content_length);
        }
    }

    const size_t total = header_end + 4 + content_length;
    if (buffer.size() < total) {
        return false;
    }
    parsed.body = buffer.substr(header_end + 4, content_length);
    consumed = total;
    request = std::move(parsed);
    return true;
}

Response make_response(const Request& request, int status, std::string reason) {
    Response response;
    response.version = request.version.empty() ? "RTSP/1.0" : request.version;
    response.status = status;
    response.reason = std::move(reason);
    if (request.cseq() != 0) {
        response.headers["CSeq"] = std::to_string(request.cseq());
    }
    response.headers["Server"] = "AirPlayC/0.1";
    return response;
}

} // namespace airplayc::rtsp
