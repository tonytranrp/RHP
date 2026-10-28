// CPace over X25519 with SHA-512 (draft-irtf-cfrg-cpace-21, CPACE-X25519-SHA512): Monocypher's
// X25519, Elligator 2 map and SHA-512.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <monocypher-ed25519.h>
#include <monocypher.h>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/security/detail/bytes.hpp>
#include <rhp/security/key.hpp>
#include <rhp/security/pairing_cpace.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::security {

namespace {

using detail::u8;

constexpr const char* kCpaceWhere = "security.cpace";
constexpr std::size_t kSha512Block = 128; // H.s_in_bytes
constexpr std::string_view kIskDsi = "CPace255_ISK";

// ---- lv_cat --------------------------------------------------------------------------------------

[[nodiscard]] constexpr std::size_t leb128_size(std::size_t n) noexcept {
    std::size_t size = 1;
    while (n >= 128) {
        n >>= 7;
        ++size;
    }
    return size;
}

// prepend_len(data), appended to `out`.
void append_lv(std::vector<std::byte>& out, std::span<const std::byte> data) {
    std::size_t n = data.size();
    do {
        const auto low = static_cast<unsigned>(n & 0x7f);
        n >>= 7;
        out.push_back(static_cast<std::byte>(n != 0 ? low | 0x80u : low));
    } while (n != 0);
    out.insert(out.end(), data.begin(), data.end());
}

void append_lv(std::vector<std::byte>& out, std::string_view text) {
    append_lv(out, std::as_bytes(std::span{text.data(), text.size()}));
}

[[nodiscard]] std::array<std::byte, 64> sha512(std::span<const std::byte> data) noexcept {
    std::array<std::byte, 64> out{};
    crypto_sha512(u8(out.data()), u8(data.data()), data.size());
    return out;
}

// ---- field elements mod p = 2^255 - 19, as 8 little-endian 32-bit limbs ---------------------------

using limbs = std::array<std::uint32_t, 8>;

constexpr limbs kP{0xffffffedu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu, 0x7fffffffu};

[[nodiscard]] limbs load_limbs(std::span<const std::byte, 32> bytes) noexcept {
    limbs out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = std::to_integer<std::uint32_t>(bytes[4 * i]) | (std::to_integer<std::uint32_t>(bytes[4 * i + 1]) << 8) |
                 (std::to_integer<std::uint32_t>(bytes[4 * i + 2]) << 16) | (std::to_integer<std::uint32_t>(bytes[4 * i + 3]) << 24);
    }
    return out;
}

void store_limbs(const limbs& value, std::span<std::byte, 32> out) noexcept {
    for (std::size_t i = 0; i < value.size(); ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            out[4 * i + j] = static_cast<std::byte>((value[i] >> (8 * j)) & 0xffu);
        }
    }
}

// a - b; returns the borrow (0 or 1).
[[nodiscard]] std::uint32_t subtract(limbs& out, const limbs& a, const limbs& b) noexcept {
    std::uint64_t borrow = 0;
    for (std::size_t i = 0; i < out.size(); ++i) {
        const std::uint64_t d = std::uint64_t{a[i]} - b[i] - borrow;
        out[i] = static_cast<std::uint32_t>(d);
        borrow = (d >> 32) & 1u;
    }
    return static_cast<std::uint32_t>(borrow);
}

// out = mask ? a : out (mask all ones or zero), without a branch.
void select(limbs& out, const limbs& a, std::uint32_t mask) noexcept {
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] ^= mask & (out[i] ^ a[i]);
    }
}

// Elligator 2 input for Monocypher: decodeUCoordinate (RFC 7748, bit 255 cleared) reduced mod p,
// then mapped below 2^254. crypto_elligator_map reads only 254 bits, and the map depends only on
// r^2, so r and p - r give the same point: for r >= 2^254 (then p - r < 2^254) it gets p - r.
void elligator_input(std::span<std::byte, 32> u) noexcept {
    u[31] &= std::byte{0x7f};
    limbs r = load_limbs(u);
    limbs t{};
    const std::uint32_t below_p = subtract(t, r, kP); // 1 when r < p
    select(r, t, below_p - 1u);                       // r >= p: r - p (< 19)
    limbs negated{};
    static_cast<void>(subtract(negated, kP, r));
    select(r, negated, 0u - ((r[7] >> 30) & 1u)); // r >= 2^254: p - r
    store_limbs(r, u);
    secure_wipe(r.data(), sizeof r);
    secure_wipe(t.data(), sizeof t);
    secure_wipe(negated.data(), sizeof negated);
}

[[nodiscard]] bool all_zero(std::span<const std::byte, 32> value) noexcept {
    constexpr std::array<std::uint8_t, 32> kZero{};
    return crypto_verify32(u8(value.data()), kZero.data()) == 0;
}

[[nodiscard]] std::array<std::byte, 32> generator(std::span<const std::byte> prs, std::span<const std::byte> ci, std::span<const std::byte> sid) {
    // generator_string(DSI, PRS, CI, sid, 128) = lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
    const std::size_t used = 1 + (leb128_size(prs.size()) + prs.size()) + (leb128_size(cpace::kDsi.size()) + cpace::kDsi.size());
    const std::size_t zpad = used < kSha512Block ? kSha512Block - used : 0;
    std::vector<std::byte> text;
    text.reserve(kSha512Block + 2 * (prs.size() + ci.size() + sid.size()) + 16);
    const utils::scope_guard wipe_text{[&text]() noexcept { secure_wipe(text.data(), text.size()); }};
    append_lv(text, cpace::kDsi);
    append_lv(text, prs);
    const std::vector<std::byte> zeros(zpad);
    append_lv(text, zeros);
    append_lv(text, ci);
    append_lv(text, sid);

    std::array<std::byte, 64> hash = sha512(text);
    std::array<std::byte, 32> u{};
    std::copy_n(hash.begin(), u.size(), u.begin());
    secure_wipe(hash.data(), hash.size());
    elligator_input(u);
    std::array<std::byte, 32> g{};
    crypto_elligator_map(u8(g.data()), u8(u.data()));
    secure_wipe(u.data(), u.size());
    return g;
}

} // namespace

result<std::array<std::byte, cpace::kMessageSize>> cpace_generator(std::span<const std::byte> prs, std::span<const std::byte> ci,
                                                                   std::span<const std::byte> sid) {
    return generator(prs, ci, sid);
}

result<cpace> cpace::start(cpace_role role, const inputs& in) {
    auto scalar = platform::random_array<kScalarSize>();
    if (!scalar) {
        return std::unexpected{std::move(scalar).error()};
    }
    auto run = start(role, in, *scalar);
    secure_wipe(scalar->data(), scalar->size());
    return run;
}

result<cpace> cpace::start(cpace_role role, const inputs& in, std::span<const std::byte, kScalarSize> scalar) {
    auto secret = key::from_bytes(scalar);
    if (!secret) {
        return std::unexpected{std::move(secret).error()};
    }
    std::array<std::byte, 32> g = generator(in.prs, in.ci, in.sid);
    cpace run;
    run.role_ = role;
    crypto_x25519(u8(run.own_.data()), u8(secret->bytes().data()), u8(g.data()));
    secure_wipe(g.data(), g.size());
    run.scalar_ = std::move(*secret);
    run.ad_.assign(in.ad.begin(), in.ad.end());
    run.sid_.assign(in.sid.begin(), in.sid.end());
    return run;
}

result<key> cpace::finish(std::span<const std::byte> peer_message, std::span<const std::byte> peer_ad) {
    if (scalar_.empty()) {
        return fail(errc::kInvalidArgument, "this CPace run has already finished", kCpaceWhere);
    }
    if (peer_message.size() != kMessageSize) {
        return fail(errc::kInvalidArgument, "a CPace message is 32 bytes", kCpaceWhere);
    }
    std::array<std::byte, 32> k{};
    const utils::scope_guard wipe_k{[&k]() noexcept { secure_wipe(k.data(), k.size()); }};
    crypto_x25519(u8(k.data()), u8(scalar_.bytes().data()), u8(peer_message.data()));
    scalar_ = key{};
    if (all_zero(k)) {
        return fail(errc::kAuth, "the peer's CPace message is a low-order point", kCpaceWhere);
    }

    // lv_cat(DSI || "_ISK", sid, K) || transcript_ir(Ya, ADa, Yb, ADb)
    std::vector<std::byte> text;
    text.reserve(kIskDsi.size() + sid_.size() + k.size() + 2 * kMessageSize + ad_.size() + peer_ad.size() + 16);
    const utils::scope_guard wipe_text{[&text]() noexcept { secure_wipe(text.data(), text.size()); }};
    append_lv(text, kIskDsi);
    append_lv(text, sid_);
    append_lv(text, k);
    const bool initiator = role_ == cpace_role::kInitiator;
    append_lv(text, initiator ? std::span<const std::byte>{own_} : peer_message);
    append_lv(text, initiator ? std::span<const std::byte>{ad_} : peer_ad);
    append_lv(text, initiator ? peer_message : std::span<const std::byte>{own_});
    append_lv(text, initiator ? peer_ad : std::span<const std::byte>{ad_});

    std::array<std::byte, kIskSize> isk = sha512(text);
    auto out = key::from_bytes(isk);
    secure_wipe(isk.data(), isk.size());
    return out;
}

namespace detail {

result<std::array<std::byte, 32>> cpace_scalar_mult_vfy(std::span<const std::byte, 32> scalar, std::span<const std::byte, 32> u) {
    std::array<std::byte, 32> out{};
    crypto_x25519(u8(out.data()), u8(scalar.data()), u8(u.data()));
    return out;
}

} // namespace detail

} // namespace Rhp::security
