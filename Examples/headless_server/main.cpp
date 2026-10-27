// headless_server: a standalone host for rhp-cli — a tiny "game" that reads its keyring and trusted
// signers from files, writes an audit log, accepts blobs into a folder, and keeps running until
// told to stop. Try the full lifecycle from another terminal:
//
//   rhp-cli keygen dev                        # writes dev.rhpid; prints the two host lines
//   echo "dev admin <psk>" > keys.txt          # the text after "keyring file:"
//   echo "dev <public key>" > signers.pub       # the text after "signers file:"
//   headless_server --port 7777 --keys keys.txt --signers signers.pub --audit audit.log
//   rhp-cli connect 127.0.0.1:7777 -i dev.rhpid
//
// Options:
//   --host H --port N        listen address (default 127.0.0.1, port required; 0 = any free port)
//   --keys FILE              keyring: `name role base64-psk` per line (required)
//   --signers FILE           trusted signers: `name base64-public-key` per line
//   --audit FILE             append every host event as a JSON line
//   --blobs DIR              blob sink "files": admins push files into DIR
//   --reverse H:N            reverse mode: dial a listening rhp-cli at H:N (instead of listening)
//   --port-file FILE         write the bound port there once listening (tests, scripts)
//   --stop-file FILE         exit once FILE exists
//   --seconds N              exit after N seconds
//   --insecure-lan           allow plaintext to and from non-loopback addresses (no TLS)
//   --tls                    TLS on every connection, loopback included
//   --cert FILE --key FILE   the host's TLS certificate chain and key (PEM); default: ephemeral self-signed
//   --ca FILE                reverse mode: check the listening rhp-cli's certificate against this CA
//   --advertise              publish the host through DNS-SD (--name, --app, --build set the record)
//   --advertise-libs         also publish the installed library names (needs --advertise)
//   --http-port N            also serve the HTTP gateway on N (0 = any free port)
//   --releases DIR           serve signed releases (rhp-cli release apply / rollout), kept in DIR across restarts
//   --release-signers FILE   who may sign them: `name base64-public-key [pattern,...]` per line (needed with --releases)
#include <atomic>
#include <charconv>
#include <chrono>
#include <concepts>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <rhp/rhp.hpp>

namespace game {

double g_gravity = -9.81;
std::int64_t g_score = 0;
std::int64_t g_tick = 0;
std::int64_t g_entities = 0;

std::int64_t spawn(std::string kind) {
    ++g_entities;
    std::println("[game] spawned a {} (entities: {})", kind, g_entities);
    return g_entities;
}

void despawn(std::int64_t) {
    --g_entities;
    std::println("[game] despawned (entities: {})", g_entities);
}

// The inverse of one addition takes exactly that addition back (it is fed the arguments).
void add_score(std::int64_t points) {
    g_score += points;
}

void remove_score(std::int64_t points) {
    g_score -= points;
}

using game_lib = Rhp::lib<"game">                            //
    ::var<"gravity", &g_gravity>                             //
    ::ro<"tick", &g_tick>                                    //
    ::ro<"entities", &g_entities>                            //
    ::ro<"score", &g_score>                                  //
    ::fn<"spawn", &spawn, Rhp::undo<&despawn>>               //
    ::fn<"add_score", &add_score, Rhp::undo<&remove_score>>; //

} // namespace game

namespace {

std::atomic<bool> g_stop{false};

extern "C" void on_signal(int) {
    g_stop.store(true);
}

struct options {
    std::string host = "127.0.0.1";
    std::optional<std::uint16_t> port;
    std::string keys;
    std::string signers;
    std::string audit;
    std::string blobs;
    std::string reverse;
    std::string port_file;
    std::string stop_file;
    int seconds = 0;
    bool insecure_lan = false;
    bool tls = false;
    std::string cert;
    std::string key;
    std::string ca;
    bool advertise = false;
    Rhp::net::advertise_options discovery;
    std::optional<std::uint16_t> http_port;
    std::string releases;
    std::string release_signers;
};

// The whole of `text` as a number (no sign, spaces or trailing characters).
template <std::integral T>
[[nodiscard]] bool parse_number(std::string_view text, T& out) {
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), out);
    return ec == std::errc{} && end == text.data() + text.size();
}

[[nodiscard]] std::optional<options> parse(int argc, char** argv) {
    options o;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        const auto value = [&]() -> std::optional<std::string> {
            if (i + 1 >= argc) {
                std::println(stderr, "{} needs a value", arg);
                return std::nullopt;
            }
            return std::string{argv[++i]};
        };
        std::optional<std::string> v;
        if (arg == "--insecure-lan") {
            o.insecure_lan = true;
            continue;
        }
        if (arg == "--tls") {
            o.tls = true;
            continue;
        }
        if (arg == "--advertise") {
            o.advertise = true;
            continue;
        }
        if (arg == "--advertise-libs") {
            o.discovery.include_libs = true;
            continue;
        }
        if (!(v = value())) {
            return std::nullopt;
        }
        if (arg == "--host") {
            o.host = *v;
        } else if (arg == "--port") {
            std::uint16_t p = 0;
            if (!parse_number(*v, p)) {
                std::println(stderr, "bad port {}", *v);
                return std::nullopt;
            }
            o.port = p;
        } else if (arg == "--keys") {
            o.keys = *v;
        } else if (arg == "--signers") {
            o.signers = *v;
        } else if (arg == "--audit") {
            o.audit = *v;
        } else if (arg == "--blobs") {
            o.blobs = *v;
        } else if (arg == "--reverse") {
            o.reverse = *v;
        } else if (arg == "--port-file") {
            o.port_file = *v;
        } else if (arg == "--stop-file") {
            o.stop_file = *v;
        } else if (arg == "--cert") {
            o.cert = *v;
        } else if (arg == "--key") {
            o.key = *v;
        } else if (arg == "--ca") {
            o.ca = *v;
        } else if (arg == "--app") {
            o.discovery.app = *v;
        } else if (arg == "--build") {
            o.discovery.build = *v;
        } else if (arg == "--name") {
            o.discovery.name = *v;
        } else if (arg == "--releases") {
            o.releases = *v;
        } else if (arg == "--release-signers") {
            o.release_signers = *v;
        } else if (arg == "--http-port") {
            std::uint16_t port = 0;
            if (!parse_number(*v, port)) {
                std::println(stderr, "invalid HTTP port");
                return std::nullopt;
            }
            o.http_port = port;
        } else if (arg == "--seconds") {
            if (!parse_number(*v, o.seconds) || o.seconds < 0) {
                std::println(stderr, "bad --seconds {}", *v);
                return std::nullopt;
            }
        } else {
            std::println(stderr, "unknown option {}", arg);
            return std::nullopt;
        }
    }
    if (o.keys.empty() || (!o.port && o.reverse.empty())) {
        std::println(stderr, "usage: headless_server --port N --keys FILE [--signers FILE] [--audit FILE] [--blobs DIR] [--reverse H:N] [--port-file FILE] [--stop-file FILE] [--seconds N] [--insecure-lan] [--tls] [--cert FILE --key FILE] [--ca FILE] [--advertise [--name N] [--app A] [--build B] [--advertise-libs]] [--http-port N] [--releases DIR --release-signers FILE]");
        return std::nullopt;
    }
    if (o.discovery.include_libs && !o.advertise) {
        std::println(stderr, "--advertise-libs requires --advertise");
        return std::nullopt;
    }
    return o;
}

// Letters, digits, '.', '_' and '-'; not starting with '.'; not a Windows device name (CON, NUL, COM1, ...).
[[nodiscard]] bool safe_file_name(const std::string& name) {
    if (name.empty() || name.size() > 128 || name.front() == '.') {
        return false;
    }
    for (const char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) {
            return false;
        }
    }
    std::string stem = name.substr(0, name.find('.'));
    for (char& c : stem) {
        c = static_cast<char>(c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c);
    }
    for (const std::string_view device : {"CON", "PRN", "AUX", "NUL"}) {
        if (stem == device) {
            return false;
        }
    }
    return !((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.size() == 4 && stem[3] >= '0' && stem[3] <= '9');
}

// The endpoint to listen on, or (reverse mode) to dial.
[[nodiscard]] std::optional<Rhp::endpoint> endpoint_of(const options& o) {
    std::optional<Rhp::endpoint> ep;
    if (o.reverse.empty()) {
        ep = o.insecure_lan ? Rhp::endpoint::listen(o.host, *o.port, Rhp::net::insecure_lan) : Rhp::endpoint::listen(o.host, *o.port);
    } else {
        const auto colon = o.reverse.rfind(':');
        std::uint16_t p = 0;
        if (colon == std::string::npos || !parse_number(std::string_view{o.reverse}.substr(colon + 1), p)) {
            std::println(stderr, "--reverse wants host:port");
            return std::nullopt;
        }
        const std::string host = o.reverse.substr(0, colon);
        ep = o.insecure_lan ? Rhp::endpoint::dial(host, p, Rhp::net::insecure_lan) : Rhp::endpoint::dial(host, p);
    }
    if (o.tls) {
        ep->tls = Rhp::net::tls_mode::kRequire;
    }
    return ep;
}

[[nodiscard]] std::optional<std::string> read_text(const std::string& path) {
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        std::println(stderr, "can't read {}", path);
        return std::nullopt;
    }
    return std::string{std::istreambuf_iterator<char>{in}, {}};
}

} // namespace

int main(int argc, char** argv) {
    const auto o = parse(argc, argv);
    if (!o) {
        return 2;
    }
    auto keys = Rhp::security::keyring::from_file(o->keys);
    if (!keys) {
        std::println(stderr, "{}", keys.error());
        return 1;
    }
    for (const std::string& warning : keys->warnings()) {
        std::println(stderr, "warning: {}", warning);
    }
    Rhp::security::trusted_signers signers;
    if (!o->signers.empty()) {
        auto loaded = Rhp::security::trusted_signers::from_file(o->signers);
        if (!loaded) {
            std::println(stderr, "{}", loaded.error());
            return 1;
        }
        signers = std::move(*loaded);
    }
    const auto ep = endpoint_of(*o);
    if (!ep) {
        return 2;
    }

    Rhp::host_options host_opts;
    if (o->http_port) {
        host_opts.gateway = Rhp::endpoint::listen(o->host, *o->http_port);
        host_opts.gateway->tls = o->tls ? Rhp::net::tls_mode::kRequire : Rhp::net::tls_mode::kAuto;
        host_opts.gateway->insecure_lan = o->insecure_lan;
    }
    for (const auto& [path, field] : {std::pair{&o->cert, &host_opts.tls.cert_pem}, std::pair{&o->key, &host_opts.tls.key_pem}, std::pair{&o->ca, &host_opts.tls.ca_pem}}) {
        if (!path->empty()) {
            auto text = read_text(*path);
            if (!text) {
                return 1;
            }
            *field = std::move(*text);
        }
    }

    using cfg = Rhp::config<>::logger<Rhp::core::stderr_logger>;
    // Releases (optional): a manager that keeps what it runs in the --releases folder. Declared
    // before the host, which serves it, so it outlives the host.
    std::optional<Rhp::release::manager> releases;
    if (!o->releases.empty()) {
        if (o->release_signers.empty()) {
            std::println(stderr, "--releases needs --release-signers");
            return 2;
        }
        auto trust = Rhp::release::trust::from_file(o->release_signers);
        if (!trust) {
            std::println(stderr, "{}", trust.error());
            return 1;
        }
        Rhp::release::manager_options ro;
        ro.app = o->discovery.app;
        ro.build = o->discovery.build;
        ro.output = [](std::string_view channel, std::string_view line) { std::println("[{}] {}", channel, line); };
        releases.emplace(std::move(*trust), std::move(ro), Rhp::release::directory_store{o->releases});
        if (auto installed = releases->install<game::game_lib>(); !installed) {
            std::println(stderr, "{}", installed.error());
            return 1;
        }
        auto restored = releases->restore();
        if (!restored) {
            std::println(stderr, "releases: {}", restored.error());
            return 1;
        }
        for (const auto& channel : restored->restored) {
            std::println("releases: {} runs again", channel);
        }
        for (const auto& [channel, err] : restored->failed) {
            std::println(stderr, "releases: {}: {}", channel, err);
        }
        for (const auto& [channel, err] : restored->deferred) {
            std::println(stderr, "releases: {} runs nothing until the next start: {}", channel, err);
        }
        for (const auto& [channel, id] : restored->quarantined) {
            std::println(stderr, "releases: {}: candidate {} quarantined", channel, Rhp::release::short_id(id));
        }
    }
    // Declared before the host so it outlives it: the reverts the host does when it shuts down are logged too.
    Rhp::event::subscription audit;
    Rhp::host<cfg> host{*ep, std::move(*keys), std::move(signers), host_opts};
    if (auto installed = host.install<game::game_lib>(); !installed) {
        std::println(stderr, "{}", installed.error());
        return 1;
    }
    if (releases) {
        if (auto served = host.serve(*releases); !served) {
            std::println(stderr, "{}", served.error());
            return 1;
        }
    }
    if (o->advertise) {
        if (auto advertised = host.advertise(o->discovery); !advertised) {
            std::println(stderr, "{}", advertised.error());
            return 1;
        }
    }
    if (o->http_port) {
        auto port = host.gateway_port();
        if (!port) {
            std::println(stderr, "{}", port.error());
            return 1;
        }
        std::println("HTTP gateway listening on {}:{}", o->host, *port);
    }

    if (!o->audit.empty()) {
        const Rhp::audit::file_sink sink{o->audit};
        if (auto ok = sink.ok(); !ok) {
            std::println(stderr, "{}", ok.error());
            return 1;
        }
        audit = host.on_any(sink);
    }
    if (!o->blobs.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(o->blobs, ec);
        if (ec) {
            std::println(stderr, "can't create {}: {}", o->blobs, ec.message());
            return 1;
        }
        const std::filesystem::path dir{o->blobs};
        auto blob_sink = host.on_blob("files", [dir](const Rhp::blob_view& b) -> Rhp::result<void> {
            // Only a plain file name: a blob can't write outside the folder (or to a device name).
            const std::filesystem::path name = std::filesystem::path{std::string{b.name}}.filename();
            if (!safe_file_name(name.string())) {
                return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("'{}' is not an accepted file name", b.name), "files");
            }
            std::ofstream out{dir / name, std::ios::binary | std::ios::trunc};
            out.write(reinterpret_cast<const char*>(b.bytes.data()), static_cast<std::streamsize>(b.bytes.size()));
            if (!out) {
                return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("can't write {}", (dir / name).string()), "files");
            }
            std::println("[game] received {} ({} bytes) from {}", name.string(), b.bytes.size(), b.identity);
            return {};
        });
        if (!blob_sink) {
            std::println(stderr, "{}", blob_sink.error());
            return 1;
        }
    }

    if (o->reverse.empty()) {
        auto port = host.port();
        if (!port) {
            std::println(stderr, "{}", port.error());
            return 1;
        }
        std::println("headless_server listening on {}:{}", o->host, *port);
        if (!o->port_file.empty()) {
            std::ofstream port_file{o->port_file};
            if (!(port_file << *port << '\n') || !port_file.flush()) {
                std::println(stderr, "can't write {}", o->port_file);
                return 1;
            }
        }
    } else {
        std::println("headless_server dialing {} (reverse mode)", o->reverse);
    }
    std::fflush(stdout);

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    const auto started = std::chrono::steady_clock::now();
    auto next_discovery_check = started;
    std::optional<Rhp::errc> discovery_problem; // reported once per change; the host keeps serving
    const char* reason = "signal";              // why the loop ended, in the last line
    while (!g_stop.load()) {
        host.pump();
        if (o->advertise && std::chrono::steady_clock::now() >= next_discovery_check) {
            const auto status = host.discovery_status();
            const auto problem = status ? std::nullopt : std::optional{status.error().code};
            if (problem != discovery_problem) {
                if (status) {
                    std::println("advertising again");
                } else {
                    std::println(stderr, "discovery: {} (still serving direct connections)", status.error());
                }
                discovery_problem = problem;
            }
            next_discovery_check = std::chrono::steady_clock::now() + std::chrono::seconds{1};
        }
        ++game::g_tick;
        std::this_thread::sleep_for(std::chrono::milliseconds{16}); // ~60 frames a second
        std::error_code ec;
        if (!o->stop_file.empty() && std::filesystem::exists(o->stop_file, ec)) {
            reason = "stop file";
            break;
        }
        if (o->seconds > 0 && std::chrono::steady_clock::now() - started > std::chrono::seconds{o->seconds}) {
            reason = "time limit";
            break;
        }
    }
    const auto ran = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    std::println("headless_server stopping after {} ms ({}; gravity {}, score {}, entities {})", ran.count(), reason, game::g_gravity, game::g_score, game::g_entities);
    return 0;
}
