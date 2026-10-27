#pragma once

// rhp-cli's connections: the terminal its network commands print to, the options they share, and
// opening a client.

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include "shell.hpp"

#include <rhp/client/client.hpp>

namespace CLI {
class App;
} // namespace CLI

namespace replxx {
class Replxx;
} // namespace replxx

namespace rhp_cli {

// Writes shell output: colored through replxx in the REPL, plain lines otherwise. Thread-safe.
class terminal {
public:
    // `to_stderr`: every line goes to stderr (stdout carries a protocol: rhp-cli dap).
    explicit terminal(replxx::Replxx* rx, bool color, bool to_stderr = false) : rx_(rx), color_(color), to_stderr_(to_stderr) {}

    void operator()(style s, std::string_view text);

private:
    replxx::Replxx* rx_;
    bool color_;
    bool to_stderr_;
    std::mutex mutex_;
};

struct connection_options {
    std::string address;
    std::string identity;
    bool insecure_lan = false;
    bool listen = false;
    bool tls = false;
    std::string ca;
    std::string server_name;
    std::string cert;
    std::string key;
    int timeout_ms = 0; // 0: 10 s when dialing, 10 min when listening
};

void add_connection_options(CLI::App& cmd, connection_options& o, bool positional_address);

// The connection a network command works over.
struct connected {
    std::unique_ptr<Rhp::client<cli_cfg>> client;
    std::unique_ptr<terminal> out;
};

[[nodiscard]] std::optional<connected> open_connection(const connection_options& o, replxx::Replxx* rx, bool to_stderr = false);

} // namespace rhp_cli
