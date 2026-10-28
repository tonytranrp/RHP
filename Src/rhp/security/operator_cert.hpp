#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/core/role.hpp>
#include <rhp/security/ed25519.hpp>
#include <rhp/security/key_handle.hpp>

namespace Rhp::security {

// Operator certificates (decision AL11, Docs/decisions/stage13-security.md "13b formats"): an
// offline operator CA vouches for an operator's key for a short time, for some apps and
// environments, up to a role. Hosts trust the CA, not each operator.
//
// The signed body is canonical MessagePack, fields in this order:
//   {serial, principal, alg, pub, not_before, not_after, max_role, apps, envs, scopes, critical}
// (lists sorted and without duplicates), signed with the CA's Ed25519 key over
// kOperatorCertDomain || body. The encoded certificate is
//   {rhp = "opcert", body = <bytes>, ca = <the CA's 32-byte public key>, sig = <64 bytes>}
// and a .rhpcert file holds it base64-armored.
inline constexpr std::string_view kOperatorCertDomain{"rhp/opcert\0", 11};

// Operator key algorithms by name (key_algorithm's names): Ed25519, or ECDSA P-256 for a key a
// hardware store holds (a key_handle); P-256 needs the TLS backend's crypto to sign and verify.
inline constexpr std::string_view kAlgEd25519 = "ed25519";
inline constexpr std::string_view kAlgP256 = "p256";

// Environment tags of CAs, certificates and claims.
inline constexpr std::string_view kEnvDev = "dev";
inline constexpr std::string_view kEnvProd = "prod";

// Size caps for decoding: lists, strings and the encoded certificate.
inline constexpr std::size_t kMaxCertListEntries = 64;
inline constexpr std::size_t kMaxCertText = 256;
inline constexpr std::size_t kMaxCertBytes = 16 * 1024;

// What a certificate says (the signed body). Times are Unix seconds; not_after is exclusive.
struct operator_cert_fields {
    std::uint64_t serial = 0;     // unique per CA: what revocations name
    std::string principal;        // the operator ("alice@ops")
    std::string alg{kAlgEd25519}; // the operator key's algorithm: "ed25519" or "p256"
    std::vector<std::byte> pub;   // the operator's public key (32 bytes for ed25519, 65 SEC1 uncompressed for p256)
    std::uint64_t not_before = 0;
    std::uint64_t not_after = 0;
    role max_role = role::kPatch;    // the most a script signed under it may run as
    std::vector<std::string> apps;   // host apps it is good for (empty: any)
    std::vector<std::string> envs;   // "dev" / "prod" (empty: any); a cert listing "dev" is a dev cert
    std::vector<std::string> scopes; // capability patterns (decision AL13; empty: no restriction)
    // Options a host must understand to accept the certificate. None is understood yet, so any
    // entry refuses it (use max_role observe for "observe-only"; "source-address" needs the peer's
    // address, which signature checks don't see).
    std::vector<std::string> critical;

    [[nodiscard]] bool operator==(const operator_cert_fields&) const = default;
};

struct operator_cert {
    operator_cert_fields fields;
    std::vector<std::byte> body;     // canonical encoding of `fields` (what the CA signed)
    ed25519_public_key ca;           // who signed it
    std::array<std::byte, 64> sig{}; // the CA's signature of kOperatorCertDomain || body

    // "<principal>#<serial>": how audit records name it.
    [[nodiscard]] std::string id() const;
    // The operator's key as an Ed25519 key; kInvalidArgument for another algorithm.
    [[nodiscard]] result<ed25519_public_key> operator_key() const;
    // The operator key's algorithm (fields.alg); kInvalidArgument for an unknown one.
    [[nodiscard]] result<key_algorithm> key_alg() const;
};

// Checks fields on their own: a serial, a principal, a known alg and key size, one scope pattern per entry, not_before <
// not_after, envs "dev" / "prod", list and text sizes.
[[nodiscard]] result<void> validate_operator_cert(const operator_cert_fields& f);

// Signs `f` (validated, lists made canonical) with the CA's key. kDisabled with RHP_ENABLE=OFF.
[[nodiscard]] result<operator_cert> issue_operator_cert(const ed25519_secret_key& ca_key, operator_cert_fields f);

// The encoded certificate, and back (strict: canonical body, known fields, exact sizes; the
// signature isn't checked here: verify does).
[[nodiscard]] result<std::vector<std::byte>> encode_operator_cert(const operator_cert& cert);
[[nodiscard]] result<operator_cert> decode_operator_cert(std::span<const std::byte> bytes);

// The .rhpcert text (a comment naming it, then the base64 between BEGIN/END lines), and back.
[[nodiscard]] result<std::string> operator_cert_to_text(const operator_cert& cert);
[[nodiscard]] result<operator_cert> operator_cert_from_text(std::string_view text);
[[nodiscard]] result<operator_cert> load_operator_cert(const std::string& path);
result<void> save_operator_cert(const std::string& path, const operator_cert& cert);

// A CA a host trusts: its name (for messages), key and environment tag ("", "dev" or "prod").
struct trusted_ca {
    std::string name;
    ed25519_public_key key;
    std::string env;
};

// The operator CAs a host trusts: a file of `name base64-public-key [env=dev|prod]` lines ('#'
// comments). Names and keys are unique.
class trusted_cas {
public:
    trusted_cas() = default;

    result<void> add(trusted_ca ca);
    [[nodiscard]] static result<trusted_cas> parse(std::string_view text);
    [[nodiscard]] static result<trusted_cas> from_file(const std::string& path);

    [[nodiscard]] const trusted_ca* find(const ed25519_public_key& key) const noexcept;
    [[nodiscard]] std::span<const trusted_ca> entries() const noexcept { return cas_; }
    [[nodiscard]] std::size_t size() const noexcept { return cas_.size(); }

private:
    std::vector<trusted_ca> cas_;
};

// The trusted-CA line for a CA key: `name base64-public-key[ env=<env>]`.
[[nodiscard]] std::string trusted_ca_line(std::string_view name, const ed25519_public_key& key, std::string_view env = {});

// Checks a certificate: signed by one of `cas` (kBadSignature otherwise), valid at `now`
// (not_before <= now < not_after, kExpired otherwise), and every critical option understood
// (none is: kForbidden). Returns the CA that signed it.
[[nodiscard]] result<const trusted_ca*> verify_operator_cert(const operator_cert& cert, const trusted_cas& cas, std::chrono::system_clock::time_point now);

// An operator CA's private key on disk (`rhp-cli ca init`), owner-only. Text:
//   name   = "ops"
//   ca_key = "base64..."     # Ed25519 seed; keep it offline
//   env    = "prod"          # optional: the tag hosts see on its trusted-CA line
struct operator_ca_key {
    std::string name;
    ed25519_secret_key secret;
    std::string env;

    [[nodiscard]] static result<operator_ca_key> generate(std::string name, std::string env = {});
    [[nodiscard]] static result<operator_ca_key> parse(std::string_view text);
    [[nodiscard]] static result<operator_ca_key> load(const std::string& path);
    [[nodiscard]] std::string to_text() const;
    result<void> save(const std::string& path) const;
    // What a host adds to its trusted-CA file.
    [[nodiscard]] std::string trusted_line() const;
};

} // namespace Rhp::security
