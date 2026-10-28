#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/security/key_handle.hpp>

namespace Rhp::security {

// One pinned host key: the endpoint a client knows the host by ("192.168.1.5:7777", "phone.local:7777")
// and the host's device-key public key.
struct known_host {
    std::string endpoint{};
    key_algorithm alg = key_algorithm::kEd25519;
    std::vector<std::byte> public_key{};

    [[nodiscard]] bool operator==(const known_host&) const = default;
};

// The host keys a device-key client trusts (decision AL10), like SSH's known_hosts. Text with one
// `endpoint alg base64-public-key` per line ('#' starts a comment); an endpoint may have several
// keys (a host whose key is being replaced). `rhp-cli` keeps one in `<config>/rhp/known_hosts`.
//
// Copies share the entries (a credential's copies see what trust on first use pinned), and every
// call is thread-safe: the client's handshake reads and adds on its network thread. A set loaded
// from a file writes it back, owner-only, on every add().
class known_hosts {
public:
    // How a host's key compares with the pins of its endpoint.
    enum class match : unsigned char {
        kPinned,  // one of the endpoint's keys
        kChanged, // the endpoint has keys, none of them this one: refuse, never ask
        kUnknown  // the endpoint has none: refuse, or ask (trust on first use)
    };

    // Empty, in memory.
    known_hosts();

    [[nodiscard]] static result<known_hosts> parse(std::string_view text);
    // The file at `path` (none yet: empty), which add() then keeps up to date. kInvalidArgument for a
    // malformed line, kNotFound when it exists and can't be read.
    [[nodiscard]] static result<known_hosts> load(const std::filesystem::path& path);

    [[nodiscard]] match check(std::string_view endpoint, key_algorithm alg, std::span<const std::byte> public_key) const;
    [[nodiscard]] std::vector<known_host> find(std::string_view endpoint) const;
    // Pins a key (nothing changes when it is pinned already). kInvalidArgument for an endpoint that is
    // empty or holds whitespace or '#', or a public key of the wrong size; a file-backed set's write
    // error (the key stays pinned in memory).
    result<void> add(known_host entry);
    [[nodiscard]] std::vector<known_host> entries() const;
    [[nodiscard]] std::string to_text() const;
    // Writes to_text() to `path`, its owner's alone (platform::write_private_file).
    result<void> save(const std::filesystem::path& path) const;

private:
    struct state;
    std::shared_ptr<state> state_;
};

} // namespace Rhp::security
