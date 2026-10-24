// remote_exec: a host and its clients in one process. The "game" runs its frame loop on its own
// thread (pumping the host); the main thread plays three developers with three keys — admin,
// patch and observe — first over the in-process loopback transport, then over TCP on 127.0.0.1.
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <rhp/rhp.hpp>

#if !defined(RHP_REMOTE_SCRIPTS_DIR)
#define RHP_REMOTE_SCRIPTS_DIR "scripts"
#endif

// ---- the "game" --------------------------------------------------------------------------------

namespace game {

std::atomic<float> g_gravity_shadow{-9.8f}; // what the frame loop last saw (main reads these)
std::atomic<int> g_score_shadow{0};
float g_gravity = -9.8f;
int g_score = 0;

// The inverse of one addition takes exactly that addition back (it is fed the arguments).
void add_score(int points) {
    g_score += points;
}

void remove_score(int points) {
    g_score -= points;
}

using game_lib = Rhp::lib<"game">                           //
    ::var<"gravity", &g_gravity>                            // writes journaled, reverted on disconnect
    ::fn<"add_score", &add_score, Rhp::undo<&remove_score>> // needs role patch
    ::ro<"score", &g_score>;                                // read-only for everyone

} // namespace game

// ---- helpers -------------------------------------------------------------------------------------

namespace {

int g_failures = 0;

template <class T>
void expect(std::string_view what, const Rhp::result<T>& r) {
    if (r) {
        std::println("  ok   {}", what);
    } else {
        ++g_failures;
        std::println("  FAIL {}: {}", what, r.error());
    }
}

template <class T>
void expect_error(std::string_view what, const Rhp::result<T>& r, Rhp::errc code) {
    if (!r && r.error().code == code) {
        std::println("  ok   {} -> {}", what, r.error());
    } else {
        ++g_failures;
        std::println("  FAIL {}: expected [{}]", what, code);
    }
}

void check(std::string_view what, bool ok) {
    std::println("  {} {}", ok ? "ok  " : "FAIL", what);
    g_failures += ok ? 0 : 1;
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream in{path, std::ios::binary};
    std::ostringstream text;
    text << in.rdbuf();
    return std::move(text).str();
}

// Waits until the game thread has seen `want` (the frame loop runs concurrently).
template <class T, class V>
bool becomes(const std::atomic<T>& shadow, V want) {
    for (int i = 0; i < 400; ++i) {
        if (shadow.load() == static_cast<T>(want)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return false;
}

bool gravity_becomes(float want) {
    return becomes(game::g_gravity_shadow, want);
}

Rhp::client_options printing(std::string_view who) {
    Rhp::client_options o;
    o.on_output = [who = std::string{who}](std::uint64_t, std::string_view line) { std::println("  [{} sees] {}", who, line); };
    return o;
}

// One tour of everything over one transport.
template <class Cfg>
void tour(std::string_view title, const Rhp::endpoint& listen_at, const Rhp::security::keyring& keys, const Rhp::security::trusted_signers& trusted,
          const Rhp::security::signing_key& developer, const Rhp::security::psk_identity& admin, const Rhp::security::psk_identity& patcher,
          const Rhp::security::psk_identity& viewer) {
    std::println("\n== {} ==", title);
    Rhp::host<Cfg> host{listen_at, keys, trusted};
    if (auto installed = host.template install<game::game_lib>(); !installed) {
        std::println("install failed: {}", installed.error());
        ++g_failures;
        return;
    }
    auto port = host.port();
    expect("host listening", port);
    if (!port) {
        return;
    }
    const Rhp::endpoint dial_at = listen_at.reversed().with_port(*port == 0 ? listen_at.port : *port);

    // The game: one thread owns the Lua states, pumping the host every ~2 ms.
    std::jthread frame_loop{[&host](std::stop_token stop) {
        while (!stop.stop_requested()) {
            host.pump();
            game::g_gravity_shadow.store(game::g_gravity);
            game::g_score_shadow.store(game::g_score);
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
    }};

    {
        // Observe runs unsigned code (it can't change anything); patch and admin sign every script.
        Rhp::client<Cfg> viewer_client{dial_at, viewer, printing("viewer")};
        auto g = viewer_client.template exec<double>("return game.gravity");
        expect("observe reads game.gravity", g);
        expect_error("observe may not write game.gravity", viewer_client.exec("game.gravity = 0"), Rhp::errc::kForbidden);
        expect_error("observe may not load a module", viewer_client.load("tuning.moon", "return {}"), Rhp::errc::kForbidden);

        {
            Rhp::client<Cfg> unsigned_patcher{dial_at, patcher};
            expect_error("an unsigned script from patch is refused", unsigned_patcher.exec("game.gravity = 0"), Rhp::errc::kBadSignature);
        }
        {
            Rhp::client<Cfg> patch_client{dial_at, patcher, developer, printing("patcher")};
            auto mod = patch_client.load("tuning.moon", read_file(std::filesystem::path{RHP_REMOTE_SCRIPTS_DIR} / "moon.lua"));
            expect("patch loads tuning.moon (moon gravity)", mod);
            check("the game sees gravity -1.6", gravity_becomes(-1.6f));
            if (mod) {
                auto score = patch_client.template exec<int>("game.add_score(10) return game.score");
                expect("patch calls a reversible binding", score);
                auto status = patch_client.status(*mod);
                expect("status over the wire", status);
                if (status) {
                    std::println("  module {} #{} {} revision {} effects {}", status->name, status->id, status->state, status->revision, status->effects);
                }
                auto stubs = patch_client.describe();
                check("describe returns LuaLS stubs", stubs && stubs->find("---@class game") != std::string::npos);
            }

            // A runaway script: cancel reaches it while the game thread is stuck inside it.
            std::jthread runaway{[&patch_client] {
                auto r = patch_client.exec("while true do end");
                std::println("  runaway script ended: {}", r ? std::string{"ok?"} : std::format("{}", r.error()));
            }};
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
            patch_client.cancel();
        } // patcher disconnects: everything it did is reverted

        check("disconnect reverted gravity to -9.8", gravity_becomes(-9.8f));
        check("disconnect reverted the score", becomes(game::g_score_shadow, 0));

        Rhp::client<Cfg> admin_client{dial_at, admin, developer, printing("admin")};
        expect("admin prints", admin_client.exec("print('hello from ' .. 'admin') return 1"));
        auto modules = admin_client.list();
        expect("admin lists its modules", modules);
        expect("admin revert_all", admin_client.revert_all());
        std::println("  sessions on the host: {}", host.sessions());
    }
    frame_loop.request_stop();
}

} // namespace

int main() {
    auto admin_key = Rhp::security::key::generate();
    auto patch_key = Rhp::security::key::generate();
    auto observe_key = Rhp::security::key::generate();
    if (!admin_key || !patch_key || !observe_key) {
        std::println(stderr, "no OS randomness for keys");
        return 1;
    }
    const Rhp::security::keyring keys{
        {"dev", *admin_key, Rhp::role::kAdmin},
        {"qa", *patch_key, Rhp::role::kPatch},
        {"viewer", *observe_key, Rhp::role::kObserve},
    };
    const Rhp::security::psk_identity admin{"dev", *admin_key};
    const Rhp::security::psk_identity patcher{"qa", *patch_key};
    const Rhp::security::psk_identity viewer{"viewer", *observe_key};
    // The developer's script-signing key: the host trusts its public half.
    auto signing = Rhp::security::ed25519_secret_key::generate();
    if (!signing) {
        std::println(stderr, "no OS randomness for the signing key");
        return 1;
    }
    const Rhp::security::signing_key developer{"dev", *signing};
    const Rhp::security::trusted_signers trusted{{"dev", signing->public_key()}};

    using loopback_cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
    using tcp_cfg = Rhp::config<>::logger<Rhp::core::null_logger>;

    tour<loopback_cfg>("loopback (in-process)", Rhp::endpoint::listen("remote_exec", 1), keys, trusted, developer, admin, patcher, viewer);
    tour<tcp_cfg>("tcp 127.0.0.1 (any free port)", Rhp::endpoint::listen("127.0.0.1", 0), keys, trusted, developer, admin, patcher, viewer);

    // A wrong key never gets a session.
    {
        using cfg = Rhp::config<>::transport<Rhp::net::loopback>::logger<Rhp::core::null_logger>;
        Rhp::host<cfg> host{Rhp::endpoint::listen("remote_exec", 2), keys};
        std::jthread frame_loop{[&host](std::stop_token stop) {
            while (!stop.stop_requested()) {
                host.pump();
                std::this_thread::sleep_for(std::chrono::milliseconds{2});
            }
        }};
        auto wrong = Rhp::security::key::generate();
        Rhp::client<cfg> intruder{Rhp::endpoint::dial("remote_exec", 2), Rhp::security::psk_identity{"dev", *wrong}};
        std::println("\n== wrong key ==");
        expect_error("a wrong key is refused", intruder.exec("return 1"), Rhp::errc::kAuth);
    }

    std::println("\nremote_exec: {}", g_failures == 0 ? "all checks passed" : std::format("{} checks FAILED", g_failures));
    return g_failures == 0 ? 0 : 1;
}
