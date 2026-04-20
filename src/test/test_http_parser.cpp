// Copyright (c) 2026 Kristian Pilatovich
// Distributed under the MIT software license.
//
// Tests for HTTP request/response parsing: GET/POST parsing, header
// extraction, Content-Length handling, keep-alive detection, basic auth,
// pipeline support, incomplete/malformed requests, parser reset,
// response serialization, status codes, CORS, and JSON body handling.

#include "consensus/params.h"
#include "hash/keccak.h"
#include "util/strencodings.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace flow;

// ---------------------------------------------------------------------------
// HttpParser — lightweight HTTP/1.1 request parser
// ---------------------------------------------------------------------------

enum class HttpParserState {
    INCOMPLETE,
    COMPLETE,
    ERROR,
};

class HttpParser {
public:
    HttpParser() { reset(); }

    void feed(const std::string& data) {
        buffer_ += data;
        parse();
    }

    HttpParserState state() const { return state_; }

    std::string method() const { return method_; }
    std::string path() const { return path_; }
    std::string version() const { return version_; }
    std::string body() const { return body_; }

    std::string get_header(const std::string& name) const {
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        auto it = headers_.find(lower);
        return (it != headers_.end()) ? it->second : "";
    }

    bool is_keep_alive() const {
        std::string conn = get_header("connection");
        if (conn.empty()) {
            // HTTP/1.1 defaults to keep-alive
            return version_ == "HTTP/1.1";
        }
        std::string lower = conn;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower == "keep-alive";
    }

    std::string get_basic_auth() const {
        std::string auth = get_header("authorization");
        if (auth.substr(0, 6) == "Basic ") {
            return auth.substr(6);
        }
        return "";
    }

    void reset() {
        buffer_.clear();
        method_.clear();
        path_.clear();
        version_.clear();
        body_.clear();
        headers_.clear();
        state_ = HttpParserState::INCOMPLETE;
        headers_complete_ = false;
        content_length_ = -1;
    }

    size_t content_length() const {
        return (content_length_ >= 0) ? static_cast<size_t>(content_length_) : 0;
    }

private:
    std::string buffer_;
    std::string method_;
    std::string path_;
    std::string version_;
    std::string body_;
    std::map<std::string, std::string> headers_;
    HttpParserState state_ = HttpParserState::INCOMPLETE;
    bool headers_complete_ = false;
    int64_t content_length_ = -1;

    void parse() {
        if (state_ == HttpParserState::ERROR) return;

        // Find end of headers
        size_t header_end = buffer_.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            // Check for obviously malformed input
            if (buffer_.size() > 65536) {
                state_ = HttpParserState::ERROR;
            }
            return;
        }

        if (!headers_complete_) {
            std::string header_section = buffer_.substr(0, header_end);
            parse_request_line(header_section);
            if (state_ == HttpParserState::ERROR) return;
            parse_headers(header_section);
            headers_complete_ = true;

            // Determine content length
            std::string cl = get_header("content-length");
            if (!cl.empty()) {
                try {
                    content_length_ = std::stoll(cl);
                } catch (...) {
                    state_ = HttpParserState::ERROR;
                    return;
                }
            } else {
                content_length_ = 0;
            }
        }

        size_t body_start = header_end + 4;
        size_t body_available = buffer_.size() - body_start;

        if (content_length_ >= 0 &&
            body_available >= static_cast<size_t>(content_length_)) {
            body_ = buffer_.substr(body_start, static_cast<size_t>(content_length_));
            state_ = HttpParserState::COMPLETE;
        }
    }

    void parse_request_line(const std::string& header_section) {
        size_t first_line_end = header_section.find("\r\n");
        std::string line = (first_line_end != std::string::npos)
            ? header_section.substr(0, first_line_end)
            : header_section;

        // Parse "METHOD PATH VERSION"
        std::istringstream iss(line);
        iss >> method_ >> path_ >> version_;

        if (method_.empty() || path_.empty()) {
            state_ = HttpParserState::ERROR;
            return;
        }

        // Validate method
        if (method_ != "GET" && method_ != "POST" && method_ != "PUT" &&
            method_ != "DELETE" && method_ != "HEAD" && method_ != "OPTIONS") {
            state_ = HttpParserState::ERROR;
        }
    }

    void parse_headers(const std::string& header_section) {
        size_t pos = header_section.find("\r\n");
        if (pos == std::string::npos) return;
        pos += 2;

        while (pos < header_section.size()) {
            size_t line_end = header_section.find("\r\n", pos);
            if (line_end == std::string::npos) line_end = header_section.size();

            std::string line = header_section.substr(pos, line_end - pos);
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = line.substr(0, colon);
                std::string value = line.substr(colon + 1);

                // Trim whitespace from value
                size_t start = value.find_first_not_of(" \t");
                if (start != std::string::npos) {
                    value = value.substr(start);
                }

                // Store headers case-insensitively
                std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                headers_[key] = value;
            }

            pos = line_end + 2;
        }
    }
};

// ---------------------------------------------------------------------------
// HttpResponse — HTTP response builder
// ---------------------------------------------------------------------------

class HttpResponse {
public:
    int status_code = 200;
    std::string status_text = "OK";
    std::map<std::string, std::string> headers;
    std::string body;
    bool cors_enabled = false;
    std::string cors_origin = "*";

    static HttpResponse ok(const std::string& body_content,
                           const std::string& content_type = "application/json") {
        HttpResponse r;
        r.status_code = 200;
        r.status_text = "OK";
        r.body = body_content;
        r.headers["Content-Type"] = content_type;
        r.headers["Content-Length"] = std::to_string(body_content.size());
        return r;
    }

    static HttpResponse error(int code, const std::string& message) {
        HttpResponse r;
        r.status_code = code;
        switch (code) {
            case 400: r.status_text = "Bad Request"; break;
            case 401: r.status_text = "Unauthorized"; break;
            case 403: r.status_text = "Forbidden"; break;
            case 404: r.status_text = "Not Found"; break;
            case 405: r.status_text = "Method Not Allowed"; break;
            case 500: r.status_text = "Internal Server Error"; break;
            default:  r.status_text = "Error"; break;
        }
        r.body = message;
        r.headers["Content-Type"] = "text/plain";
        r.headers["Content-Length"] = std::to_string(message.size());
        return r;
    }

    void add_cors_headers() {
        cors_enabled = true;
        headers["Access-Control-Allow-Origin"] = cors_origin;
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization";
    }

    std::string serialize() const {
        std::ostringstream ss;
        ss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
        for (const auto& [key, value] : headers) {
            ss << key << ": " << value << "\r\n";
        }
        ss << "\r\n" << body;
        return ss.str();
    }
};

void test_http_parser() {

    // -----------------------------------------------------------------------
    // Test 1: Parse simple GET request
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("GET /rest/chaininfo.json HTTP/1.1\r\n"
                     "Host: localhost:9334\r\n"
                     "\r\n");

        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.method() == "GET");
        assert(parser.path() == "/rest/chaininfo.json");
        assert(parser.version() == "HTTP/1.1");
        assert(parser.body().empty());
    }

    // -----------------------------------------------------------------------
    // Test 2: Parse POST with body
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        std::string body = R"({"method":"getblockcount","params":[],"id":1})";
        std::string request =
            "POST / HTTP/1.1\r\n"
            "Host: localhost:9334\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "\r\n" + body;

        parser.feed(request);

        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.method() == "POST");
        assert(parser.body() == body);
        assert(parser.content_length() == body.size());
    }

    // -----------------------------------------------------------------------
    // Test 3: Parse headers (case insensitive)
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("GET / HTTP/1.1\r\n"
                     "Host: localhost\r\n"
                     "Content-Type: application/json\r\n"
                     "X-Custom-Header: test-value\r\n"
                     "\r\n");

        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.get_header("host") == "localhost");
        assert(parser.get_header("Host") == "localhost");
        assert(parser.get_header("HOST") == "localhost");
        assert(parser.get_header("content-type") == "application/json");
        assert(parser.get_header("x-custom-header") == "test-value");
        assert(parser.get_header("nonexistent") == "");
    }

    // -----------------------------------------------------------------------
    // Test 4: Content-Length determines body size
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        std::string body = "hello";
        parser.feed("POST / HTTP/1.1\r\n"
                     "Content-Length: 5\r\n"
                     "\r\n"
                     "helloextra_data_ignored");

        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.body() == "hello");
        assert(parser.body().size() == 5);
    }

    // -----------------------------------------------------------------------
    // Test 5: Keep-alive detection
    // -----------------------------------------------------------------------
    {
        // HTTP/1.1 defaults to keep-alive
        HttpParser parser1;
        parser1.feed("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert(parser1.is_keep_alive());

        // Explicit close
        HttpParser parser2;
        parser2.feed("GET / HTTP/1.1\r\nConnection: close\r\n\r\n");
        assert(!parser2.is_keep_alive());

        // Explicit keep-alive
        HttpParser parser3;
        parser3.feed("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        assert(parser3.is_keep_alive());
    }

    // -----------------------------------------------------------------------
    // Test 6: Basic auth parsing
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("GET / HTTP/1.1\r\n"
                     "Authorization: Basic dXNlcjpwYXNz\r\n"
                     "\r\n");

        assert(parser.state() == HttpParserState::COMPLETE);
        std::string auth = parser.get_basic_auth();
        assert(auth == "dXNlcjpwYXNz");  // base64("user:pass")
    }

    // -----------------------------------------------------------------------
    // Test 7: Multiple requests on same connection (pipeline)
    // -----------------------------------------------------------------------
    {
        // Parse first request
        HttpParser parser;
        parser.feed("GET /block/1 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.path() == "/block/1");

        // Reset and parse second request
        parser.reset();
        parser.feed("GET /block/2 HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.path() == "/block/2");
    }

    // -----------------------------------------------------------------------
    // Test 8: Incomplete request -> state not COMPLETE
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("GET / HTTP/1.1\r\n");
        assert(parser.state() == HttpParserState::INCOMPLETE);

        parser.feed("Host: localhost\r\n");
        assert(parser.state() == HttpParserState::INCOMPLETE);

        // Complete the request
        parser.feed("\r\n");
        assert(parser.state() == HttpParserState::COMPLETE);
    }

    // -----------------------------------------------------------------------
    // Test 9: Malformed request -> ERROR state
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("INVALID_GARBAGE_DATA\r\n\r\n");
        assert(parser.state() == HttpParserState::ERROR);
    }

    // -----------------------------------------------------------------------
    // Test 10: Reset and reuse parser
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("GET /first HTTP/1.1\r\n\r\n");
        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.path() == "/first");

        parser.reset();
        assert(parser.state() == HttpParserState::INCOMPLETE);
        assert(parser.method().empty());
        assert(parser.path().empty());

        parser.feed("POST /second HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.path() == "/second");
        assert(parser.method() == "POST");
    }

    // -----------------------------------------------------------------------
    // Test 11: HttpResponse serialization
    // -----------------------------------------------------------------------
    {
        auto resp = HttpResponse::ok("{\"result\":42}", "application/json");
        std::string serialized = resp.serialize();

        assert(serialized.find("HTTP/1.1 200 OK") != std::string::npos);
        assert(serialized.find("Content-Type: application/json") != std::string::npos);
        assert(serialized.find("{\"result\":42}") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 12: HttpResponse status codes
    // -----------------------------------------------------------------------
    {
        auto r400 = HttpResponse::error(400, "Bad Request");
        assert(r400.status_code == 400);
        assert(r400.status_text == "Bad Request");

        auto r404 = HttpResponse::error(404, "Not Found");
        assert(r404.status_code == 404);
        assert(r404.status_text == "Not Found");

        auto r500 = HttpResponse::error(500, "Internal Error");
        assert(r500.status_code == 500);
        assert(r500.status_text == "Internal Server Error");
    }

    // -----------------------------------------------------------------------
    // Test 13: HttpResponse CORS headers
    // -----------------------------------------------------------------------
    {
        auto resp = HttpResponse::ok("{}", "application/json");
        resp.add_cors_headers();

        assert(resp.cors_enabled);
        assert(resp.headers.count("Access-Control-Allow-Origin") > 0);
        assert(resp.headers["Access-Control-Allow-Origin"] == "*");
        assert(resp.headers.count("Access-Control-Allow-Methods") > 0);

        std::string serialized = resp.serialize();
        assert(serialized.find("Access-Control-Allow-Origin: *") != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 14: HttpResponse JSON body
    // -----------------------------------------------------------------------
    {
        std::string json_body = R"({"jsonrpc":"2.0","result":{"height":100},"id":1})";
        auto resp = HttpResponse::ok(json_body, "application/json");

        assert(resp.body == json_body);
        assert(resp.headers["Content-Length"] == std::to_string(json_body.size()));

        std::string serialized = resp.serialize();
        assert(serialized.find(json_body) != std::string::npos);
    }

    // -----------------------------------------------------------------------
    // Test 15: POST with empty body and Content-Length: 0
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("POST / HTTP/1.1\r\n"
                     "Content-Length: 0\r\n"
                     "\r\n");

        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.body().empty());
        assert(parser.content_length() == 0);
    }

    // -----------------------------------------------------------------------
    // Test 16: No Authorization header -> empty auth
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert(parser.get_basic_auth().empty());
    }

    // -----------------------------------------------------------------------
    // Test 17: Custom CORS origin
    // -----------------------------------------------------------------------
    {
        auto resp = HttpResponse::ok("{}", "application/json");
        resp.cors_origin = "https://example.com";
        resp.add_cors_headers();

        assert(resp.headers["Access-Control-Allow-Origin"] == "https://example.com");
    }

    // -----------------------------------------------------------------------
    // Test 18: Response with 401 Unauthorized
    // -----------------------------------------------------------------------
    {
        auto resp = HttpResponse::error(401, "Authentication required");
        assert(resp.status_code == 401);
        assert(resp.status_text == "Unauthorized");
        assert(resp.body == "Authentication required");
    }

    // -----------------------------------------------------------------------
    // Test 19: Incremental feed builds complete request
    // -----------------------------------------------------------------------
    {
        HttpParser parser;
        parser.feed("GET /api/v1/");
        assert(parser.state() == HttpParserState::INCOMPLETE);

        parser.feed("status HTTP/1.1\r\n");
        assert(parser.state() == HttpParserState::INCOMPLETE);

        parser.feed("Host: localhost\r\n\r\n");
        assert(parser.state() == HttpParserState::COMPLETE);
        assert(parser.path() == "/api/v1/status");
    }

    // -----------------------------------------------------------------------
    // Test 20: Response serialization ordering
    // -----------------------------------------------------------------------
    {
        auto resp = HttpResponse::ok("test body", "text/plain");
        std::string s = resp.serialize();

        // Status line must come first
        assert(s.find("HTTP/1.1 200 OK\r\n") == 0);

        // Body comes after the blank line
        size_t blank = s.find("\r\n\r\n");
        assert(blank != std::string::npos);
        std::string body_part = s.substr(blank + 4);
        assert(body_part == "test body");
    }
}
