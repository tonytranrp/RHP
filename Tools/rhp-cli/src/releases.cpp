// rhp-cli release / revoke: building, signing and inspecting .rhprel / .rhprev files.
#include <chrono>
#include <cstddef>
#include <format>
#include <print>
#include <string>
#include <vector>

#include "commands.hpp"
#include "release_files.hpp"

#include <rhp/release/release.hpp>
#include <rhp/security/identity_file.hpp>

namespace rhp_cli {

namespace {

// Adds the identity's signature to a release or revocation file (in place).
template <class Doc, class Decode, class Encode>
int sign_file(const std::string& path, const std::string& identity, Decode decode, Encode encode) {
    auto id = Rhp::security::identity_file::load(identity);
    auto bytes = rhp_cli::read_binary_file(path);
    if (!id || !bytes) {
        std::println(stderr, "{}", !id ? std::format("{}", id.error()) : std::format("can't read {}", path));
        return 1;
    }
    auto key = id->signer_key();
    if (!key) {
        std::println(stderr, "{} has no signing_key", identity);
        return 1;
    }
    auto doc = decode(*bytes);
    if (!doc) {
        std::println(stderr, "{}", doc.error());
        return 1;
    }
    if (auto signed_ok = Rhp::release::sign(*doc, *key); !signed_ok) {
        std::println(stderr, "{}", signed_ok.error());
        return 1;
    }
    auto out = encode(*doc);
    if (!out || !rhp_cli::write_binary_file(path, *out)) {
        std::println(stderr, "can't write {}", path);
        return 1;
    }
    std::println("{}: signed by {} ({} signatures)", path, key->name, doc->signatures.size());
    return 0;
}

} // namespace

int release_build(const rhp_cli::release_spec& spec, const std::vector<std::string>& identities, const std::string& out_path) {
    auto r = rhp_cli::build_release(spec, std::chrono::system_clock::now());
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    for (const std::string& identity : identities) {
        auto id = Rhp::security::identity_file::load(identity);
        auto key = id ? id->signer_key() : std::nullopt;
        if (!key) {
            std::println(stderr, "{}: no signing key", identity);
            return 1;
        }
        if (auto ok = Rhp::release::sign(*r, *key); !ok) {
            std::println(stderr, "{}", ok.error());
            return 1;
        }
    }
    auto bytes = Rhp::release::encode_release(*r);
    const std::string path = out_path.empty() ? std::format("{}.{}.rhprel", r->body.channel, r->body.seq) : out_path;
    if (!bytes || !rhp_cli::write_binary_file(path, *bytes)) {
        std::println(stderr, "can't write {}", path);
        return 1;
    }
    std::print("{}", rhp_cli::describe(*r));
    std::println("wrote {}", path);
    return 0;
}

int revoke_build(const rhp_cli::revocation_spec& spec, const std::vector<std::string>& identities, const std::string& out_path) {
    auto r = rhp_cli::build_revocations(spec, std::chrono::system_clock::now());
    if (!r) {
        std::println(stderr, "{}", r.error());
        return 1;
    }
    for (const std::string& identity : identities) {
        auto id = Rhp::security::identity_file::load(identity);
        auto key = id ? id->signer_key() : std::nullopt;
        if (!key) {
            std::println(stderr, "{}: no signing key", identity);
            return 1;
        }
        if (auto ok = Rhp::release::sign(*r, *key); !ok) {
            std::println(stderr, "{}", ok.error());
            return 1;
        }
    }
    auto bytes = Rhp::release::encode_revocations(*r);
    const std::string path = out_path.empty() ? std::format("revocations.{}.rhprev", r->body.seq) : out_path;
    if (!bytes || !rhp_cli::write_binary_file(path, *bytes)) {
        std::println(stderr, "can't write {}", path);
        return 1;
    }
    std::print("{}", rhp_cli::describe(*r));
    std::println("wrote {}", path);
    return 0;
}

int release_sign(const std::string& file, const std::string& identity) {
    return sign_file<Rhp::release::release>(
        file, identity, [](const std::vector<std::byte>& b) { return Rhp::release::decode_release(b); },
        [](const Rhp::release::release& r) { return Rhp::release::encode_release(r); });
}

int revoke_sign(const std::string& file, const std::string& identity) {
    return sign_file<Rhp::release::signed_revocations>(
        file, identity, [](const std::vector<std::byte>& b) { return Rhp::release::decode_revocations(b); },
        [](const Rhp::release::signed_revocations& r) { return Rhp::release::encode_revocations(r); });
}

int inspect(const std::string& path) {
    auto bytes = rhp_cli::read_binary_file(path);
    if (!bytes) {
        std::println(stderr, "can't read {}", path);
        return 1;
    }
    auto release = Rhp::release::decode_release(*bytes);
    if (release) {
        std::print("{}", rhp_cli::describe(*release));
        return 0;
    }
    auto revocations = Rhp::release::decode_revocations(*bytes);
    if (revocations) {
        std::print("{}", rhp_cli::describe(*revocations));
        return 0;
    }
    // The error of the kind of document the file says it is.
    const bool says_revocations = rhp_cli::document_tag(*bytes) == "revocations-envelope";
    std::println(stderr, "{}: {}", path, says_revocations ? revocations.error() : release.error());
    return 1;
}

} // namespace rhp_cli
