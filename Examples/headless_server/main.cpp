// headless_server: a standalone host for rhp-cli — a tiny "game" that reads its keyring and trusted
// signers from files, writes an audit log, accepts blobs into a folder, and keeps running until
// told to stop. Try the full lifecycle from another terminal:
//
//   rhp-cli keygen dev                        # prints the two lines below
//   echo "dev admin <psk>" > keys.txt
//   echo "dev <public key>" > signers.pub
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
//   --insecure-lan           allow a non-loopback address without TLS
#include <atomic>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
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

std::int64_t add_score(std::int64_t points) {
    g_score += points;
    return g_score;
}

void remove_score(std::int64_t) {
    g_score = 0;
}

using game_lib = Rhp::lib<"game">                            //
    ::var<"gravity", &g_gravity>                             //
    ::ro<"tick", &g_tick>                                    //
    ::ro<"entities", &g_entities>                            //
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
};

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
        if (!(v = value())) {
            return std::nullopt;
        }
        if (arg == "--host") {
            o.host = *v;
        } else if (arg == "--port") {
            std::uint16_t p = 0;
            if (std::from_chars(v->data(), v->data() + v->size(), p).ec != std::errc{}) {
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
        } else if (arg == "--seconds") {
            std::from_chars(v->data(), v->data() + v->size(), o.seconds);
        } else {
            std::println(stderr, "unknown option {}", arg);
            return std::nullopt;
        }
    }
    if (o.keys.empty() || (!o.port && o.reverse.empty())) {
        std::println(stderr, "usage: headless_server --port N --keys FILE [--signers FILE] [--audit FILE] [--blobs DIR] [--reverse H:N]");
        return std::nullopt;
    }
    return o;
}

// The endpoint to listen on, or (reverse mode) to dial.
[[nodiscard]] std::optional<Rhp::endpoint> endpoint_of(const options& o) {
    if (o.reverse.empty()) {
        return o.insecure_lan ? Rhp::endpoint::listen(o.host, *o.port, Rhp::net::insecure_lan) : Rhp::endpoint::listen(o.host, *o.port);
    }
    const auto colon = o.reverse.rfind(':');
    std::uint16_t p = 0;
    if (colon == std::string::npos || std::from_chars(o.reverse.data() + colon + 1, o.reverse.data() + o.reverse.size(), p).ec != std::errc{}) {
        std::println(stderr, "--reverse wants host:port");
        return std::nullopt;
    }
    const std::string host = o.reverse.substr(0, colon);
    return o.insecure_lan ? Rhp::endpoint::dial(host, p, Rhp::net::insecure_lan) : Rhp::endpoint::dial(host, p);
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

    using cfg = Rhp::config<>::logger<Rhp::core::stderr_logger>;
    Rhp::host<cfg> host{*ep, std::move(*keys), std::move(signers)};
    if (auto installed = host.install<game::game_lib>(); !installed) {
        std::println(stderr, "{}", installed.error());
        return 1;
    }

    Rhp::event::subscription audit;
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
        const std::filesystem::path dir{o->blobs};
        (void)host.on_blob("files", [dir](const Rhp::blob_view& b) -> Rhp::result<void> {
            // Only a plain file name: a blob can't write outside the folder.
            const std::filesystem::path name = std::filesystem::path{std::string{b.name}}.filename();
            if (name.empty() || name == "." || name == "..") {
                return Rhp::fail(Rhp::errc::kInvalidArgument, "the blob needs a file name", "files");
            }
            std::ofstream out{dir / name, std::ios::binary | std::ios::trunc};
            out.write(reinterpret_cast<const char*>(b.bytes.data()), static_cast<std::streamsize>(b.bytes.size()));
            if (!out) {
                return Rhp::fail(Rhp::errc::kInvalidArgument, std::format("can't write {}", (dir / name).string()), "files");
            }
            std::println("[game] received {} ({} bytes) from {}", name.string(), b.bytes.size(), b.identity);
            return {};
        });
    }

    if (o->reverse.empty()) {
        auto port = host.port();
        if (!port) {
            std::println(stderr, "{}", port.error());
            return 1;
        }
        std::println("headless_server listening on {}:{}", o->host, *port);
        if (!o->port_file.empty()) {
            std::ofstream{o->port_file} << *port << '\n';
        }
    } else {
        std::println("headless_server dialing {} (reverse mode)", o->reverse);
    }
    std::fflush(stdout);

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    const auto started = std::chrono::steady_clock::now();
    while (!g_stop.load()) {
        host.pump();
        ++game::g_tick;
        std::this_thread::sleep_for(std::chrono::milliseconds{16}); // ~60 frames a second
        std::error_code ec;
        if (!o->stop_file.empty() && std::filesystem::exists(o->stop_file, ec)) {
            break;
        }
        if (o->seconds > 0 && std::chrono::steady_clock::now() - started > std::chrono::seconds{o->seconds}) {
            break;
        }
    }
    std::println("headless_server stopping (gravity {}, score {}, entities {})", game::g_gravity, game::g_score, game::g_entities);
    return 0;
}
