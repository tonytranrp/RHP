#pragma once

// rhp-cli's release files: building, signing and describing .rhprel / .rhprev files. No network:
// main.cpp sends them.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <string>
#include <vector>

#include <rhp/client/rollout.hpp>
#include <rhp/core/result.hpp>
#include <rhp/release/release.hpp>
#include <rhp/wire/messages.hpp>

namespace rhp_cli {

// What `rhp-cli release build` takes.
struct release_spec {
    std::string channel;
    std::string seq = "auto"; // a number, or "auto": the current Unix time in seconds
    std::string label;
    std::string app;
    std::vector<std::string> builds;
    std::vector<std::string> platforms;
    std::uint64_t not_before = 0;
    std::uint64_t not_after = 0;
    std::string role = "patch";
    std::vector<std::string> libs;
    std::vector<std::string> fail_events;
    std::uint32_t max_handler_failures = 0;
    // "path" (module named after the file, as `run` names it) or "name=path", in load order.
    std::vector<std::string> modules;
};

[[nodiscard]] Rhp::result<Rhp::release::release> build_release(const release_spec& spec, std::chrono::system_clock::time_point now);

// What `rhp-cli revoke build` takes.
struct revocation_spec {
    std::string seq = "auto";
    std::vector<std::string> releases; // release ids, hex
    std::vector<std::string> keys;     // Ed25519 public keys, base64
    std::vector<std::string> floors;   // "channel=seq"
};

[[nodiscard]] Rhp::result<Rhp::release::signed_revocations> build_revocations(const revocation_spec& spec, std::chrono::system_clock::time_point now);

// The "rhp" tag of a MessagePack document ("release-envelope", ...); empty when it has none.
[[nodiscard]] std::string document_tag(std::span<const std::byte> bytes);

// "fraction:observe_ms" (observe_ms optional) for rhp-cli rollout --stage; the whole text must
// parse and the fraction lie in [0, 1].
[[nodiscard]] std::optional<Rhp::rollout_stage> parse_stage(std::string_view text);

[[nodiscard]] Rhp::result<std::vector<std::byte>> read_binary_file(const std::filesystem::path& path);
[[nodiscard]] Rhp::result<void> write_binary_file(const std::filesystem::path& path, const std::vector<std::byte>& bytes);

// Human-readable descriptions (`release inspect`, `release status`).
[[nodiscard]] std::string describe(const Rhp::release::release& r);
[[nodiscard]] std::string describe(const Rhp::release::signed_revocations& r);
[[nodiscard]] std::string describe(const Rhp::wire::release_status_reply& status);

} // namespace rhp_cli
