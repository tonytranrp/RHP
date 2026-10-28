#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <rhp/core/result.hpp>

// The OS's own places for keys, behind portable calls (what security's key stores build on). Each
// reports kDisabled where its OS service doesn't exist. Returned plaintext is the caller's to wipe.
namespace Rhp::platform {

// Windows DPAPI for the current user (CryptProtectData): `plain` sealed so that only this user, on
// this machine, can open it again. kDisabled on other OSes.
[[nodiscard]] result<std::vector<std::byte>> protect(std::span<const std::byte> plain);

// The plaintext of what protect() sealed; kAuth when it can't be opened (another user's, another
// machine's, damaged). kDisabled on other OSes.
[[nodiscard]] result<std::vector<std::byte>> unprotect(std::span<const std::byte> sealed);

// Apple Keychain generic passwords (kSecClassGenericPassword), found by service and account. Stored
// items are this device's only, readable after the first unlock. kDisabled on other OSes.
[[nodiscard]] result<std::vector<std::byte>> keychain_load(std::string_view service, std::string_view account); // kNotFound
[[nodiscard]] result<void> keychain_store(std::string_view service, std::string_view account, std::span<const std::byte> secret);
[[nodiscard]] result<void> keychain_remove(std::string_view service, std::string_view account); // kNotFound

// One line typed on the terminal without echo (a passphrase), after writing `prompt` to standard
// error. kDisabled when standard input isn't a terminal; kNotFound at end of input.
[[nodiscard]] result<std::string> read_secret_line(std::string_view prompt);

} // namespace Rhp::platform
