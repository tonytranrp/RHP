#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>
#include <rhp/security/key.hpp>

namespace Rhp::security {

// CPace, the balanced PAKE of draft-irtf-cfrg-cpace (checked against revision 21's test vectors),
// suite CPACE-X25519-SHA512, in the initiator-responder setting (transcript_ir). Pairing runs it
// over a 6-digit code (decision AL10): both sides end with the same 64-byte ISK only when they used
// the same PRS, CI and sid and saw the same messages; a wrong code gives unrelated keys, and each
// run tests one guess.
//
//   g   = map_to_curve_elligator2(decodeUCoordinate(SHA-512(lv_cat(DSI, PRS, zpad, CI, sid))[0..32]))
//         DSI = "CPace255"; zpad fills the first 128-byte SHA-512 block after DSI and PRS
//   Y   = X25519(y, g)                    y: 32 random bytes; Y is the message (32 bytes)
//   K   = X25519(y, Y_peer)               refused when all zero (a low-order point): kAuth
//   ISK = SHA-512(lv_cat("CPace255_ISK", sid, K) || lv_cat(Ya, ADa) || lv_cat(Yb, ADb))
//
// lv_cat prefixes each string with its length in LEB128. ADa / ADb are the initiator's and the
// responder's associated data: sent in clear next to Ya / Yb and authenticated by the ISK. K never
// leaves this class. The ISK confirms nothing by itself: the caller proves it (a MAC under a key
// derived from it, or frame keys that fail to verify) before trusting the peer.
//
// The scalar is wiped when finish() returns or the object goes; the generator and the hashed
// strings (which hold the PRS) are wiped as soon as they are used. The generator is computed in
// constant time; X25519 and the all-zero test are Monocypher's (constant time). With
// RHP_ENABLE=OFF everything here reports kDisabled.
enum class cpace_role : unsigned char {
    kInitiator, // A: sends Ya first (the client)
    kResponder  // B: answers with Yb (the host)
};

class cpace {
public:
    static constexpr std::size_t kMessageSize = 32; // Ya, Yb: an X25519 u-coordinate
    static constexpr std::size_t kScalarSize = 32;
    static constexpr std::size_t kIskSize = 64;
    static constexpr std::string_view kDsi = "CPace255";

    // What both sides must agree on, and this side's associated data. Copied by start().
    struct inputs {
        std::span<const std::byte> prs{}; // the password-related string
        std::span<const std::byte> ci{};  // channel identifier: never sent, may be secret
        std::span<const std::byte> sid{}; // session identifier: unique per run when there is one
        std::span<const std::byte> ad{};  // this side's ADa (initiator) or ADb (responder)
    };

    // A run with a fresh random scalar.
    [[nodiscard]] static result<cpace> start(cpace_role role, const inputs& in);
    // A run with a given scalar (the draft's test vectors). Never reuse a scalar.
    [[nodiscard]] static result<cpace> start(cpace_role role, const inputs& in, std::span<const std::byte, kScalarSize> scalar);

    cpace(const cpace&) = delete;
    cpace& operator=(const cpace&) = delete;
    cpace(cpace&&) noexcept = default;
    cpace& operator=(cpace&&) noexcept = default;
    ~cpace() = default;

    [[nodiscard]] cpace_role role() const noexcept { return role_; }
    // Ya or Yb: what this side sends (with associated_data()).
    [[nodiscard]] std::span<const std::byte, kMessageSize> message() const noexcept { return own_; }
    [[nodiscard]] std::span<const std::byte> associated_data() const noexcept { return ad_; }

    // The ISK (kIskSize bytes, wiped with the key) from the peer's message and associated data.
    // Once per run: kInvalidArgument for a message that isn't kMessageSize bytes or a second call;
    // kAuth when the peer's point gives the neutral element (a low-order point, on the curve or its
    // twist).
    [[nodiscard]] result<key> finish(std::span<const std::byte> peer_message, std::span<const std::byte> peer_ad = {});

private:
    cpace() = default;

    cpace_role role_ = cpace_role::kInitiator;
    key scalar_; // empty once finished
    std::array<std::byte, kMessageSize> own_{};
    std::vector<std::byte> ad_;
    std::vector<std::byte> sid_;
};

// G.calculate_generator(SHA-512, PRS, CI, sid): the draft's generator g (tests check it against the
// vectors). Secret: it is derived from the PRS.
[[nodiscard]] result<std::array<std::byte, cpace::kMessageSize>> cpace_generator(std::span<const std::byte> prs, std::span<const std::byte> ci,
                                                                                 std::span<const std::byte> sid);

namespace detail {

// G_X25519.scalar_mult_vfy(y, u): X25519, all zero for a low-order u (the draft's B.1.10 vectors).
// Not part of a run's interface: a run never shows K.
[[nodiscard]] result<std::array<std::byte, 32>> cpace_scalar_mult_vfy(std::span<const std::byte, 32> scalar, std::span<const std::byte, 32> u);

} // namespace detail

} // namespace Rhp::security
