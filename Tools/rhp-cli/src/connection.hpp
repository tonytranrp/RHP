#pragma once

// rhp-cli's connections: the terminal its network commands print to, the options they share,
// opening a client (or a dev session's), and loading the identity that signs.

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "shell.hpp"

#include <rhp/client/client.hpp>
#include <rhp/net/local/local.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/identity_file.hpp>

namespace CLI {
class App;
} // namespace CLI

namespace replxx {
class Replxx;
} // namespace replxx

namespace rhp_cli {

// Dev sessions on local IPC (connect --dev): the REPL over a named pipe or a Unix socket.
using cli_ipc_cfg = Rhp::config<>::transport<Rhp::net::local_ipc>::logger<Rhp::core::null_logger>;

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
    // Sign with this operator certificate (.rhpcert) and the identity's signing key, which it must name;
    // the claims name the identity and, when given, the host's app, environment and id.
    std::string cert_file;
    std::string claim_app;
    std::string claim_env;
    std::string claim_audience;
    int timeout_ms = 0; // 0: 10 s when dialing, 10 min when listening
};

// `required`: the address and -i/--identity must be given (connect checks them itself: --dev reads
// both from the dev session file).
void add_connection_options(CLI::App& cmd, connection_options& o, bool positional_address, bool required = true);

// The connection a network command works over.
template <class Cfg>
struct connection {
    std::unique_ptr<Rhp::client<Cfg>> client;
    std::unique_ptr<terminal> out;
};
using connected = connection<cli_cfg>;
// A dev session's: over TCP on loopback, or local IPC.
using dev_connected = std::variant<connection<cli_cfg>, connection<cli_ipc_cfg>>;

[[nodiscard]] std::optional<connected> open_connection(const connection_options& o, replxx::Replxx* rx, bool to_stderr = false);

// connect --dev [app]: the dev session file pick_dev_session chooses in the user's config folder,
// connected with its endpoint (refused unless loopback or local IPC) and identity.
[[nodiscard]] std::optional<dev_connected> open_dev_connection(std::string_view app, int timeout_ms, replxx::Replxx* rx);

// The passphrase for the signing key file beside the identity file at `identity_path`:
// RHP_PASSPHRASE, else typed on the terminal when that file is sealed, else "".
[[nodiscard]] std::string signing_passphrase(const std::string& identity_path);

// identity_file::load (with the signing key file beside it, opened with signing_passphrase), its
// warnings printed first ("warning: ..."); nullopt after printing the error. Through `out` when
// given, else to stderr.
[[nodiscard]] std::optional<Rhp::security::identity_file> load_identity(const std::string& path, terminal* out = nullptr);

// An identity that signs scripts and release files.
struct signer {
    Rhp::security::identity_file id;
    Rhp::security::signing_key key;
};

// The identity file at `path` with its signing key; nullopt, after printing why, when it can't be
// loaded (the load's own error) or has no signing_key.
[[nodiscard]] std::optional<signer> load_signer(const std::string& path);

} // namespace rhp_cli
