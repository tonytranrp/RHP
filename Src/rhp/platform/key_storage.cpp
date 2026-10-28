// DPAPI (Windows), the Keychain (Apple) and reading a passphrase without echo. The Keychain code is
// compiled on Apple targets only and hasn't run on one yet: it follows Apple's documented
// SecItem* calls (SecItemCopyMatching, SecItemAdd, SecItemDelete) and nothing more.
#include <cstddef>
#include <cstdio>
#include <format>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/key_storage.hpp>
#include <rhp/utils/scope_guard.hpp>

#if defined(RHP_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// After windows.h:
#include <wincrypt.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#if defined(RHP_PLATFORM_MACOS) || defined(RHP_PLATFORM_IOS)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace Rhp::platform {

namespace {

[[maybe_unused]] constexpr const char* kStorageWhere = "platform.key_storage";

} // namespace

// ---- DPAPI ----------------------------------------------------------------------------------------

#if defined(RHP_PLATFORM_WINDOWS)

namespace {

// Ties RHP's blobs to RHP: another program's CryptUnprotectData of them without it fails.
constexpr std::string_view kEntropy{"rhp/dpapi\0", 10};

[[nodiscard]] DATA_BLOB blob_of(std::span<const std::byte> bytes) noexcept {
    return DATA_BLOB{static_cast<DWORD>(bytes.size()), reinterpret_cast<BYTE*>(const_cast<std::byte*>(bytes.data()))};
}

// What DPAPI returned, wiped and freed when it goes.
[[nodiscard]] std::vector<std::byte> take(DATA_BLOB& out) {
    std::vector<std::byte> bytes(reinterpret_cast<const std::byte*>(out.pbData), reinterpret_cast<const std::byte*>(out.pbData) + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    out.pbData = nullptr;
    return bytes;
}

} // namespace

result<std::vector<std::byte>> protect(std::span<const std::byte> plain) {
    DATA_BLOB in = blob_of(plain);
    DATA_BLOB entropy = blob_of(std::as_bytes(std::span{kEntropy}));
    DATA_BLOB out{};
    if (CryptProtectData(&in, L"rhp key", &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        return fail(errc::kRuntime, std::format("CryptProtectData failed (error {})", GetLastError()), kStorageWhere);
    }
    return take(out);
}

result<std::vector<std::byte>> unprotect(std::span<const std::byte> sealed) {
    DATA_BLOB in = blob_of(sealed);
    DATA_BLOB entropy = blob_of(std::as_bytes(std::span{kEntropy}));
    DATA_BLOB out{};
    if (CryptUnprotectData(&in, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out) == 0) {
        return fail(errc::kAuth, std::format("CryptUnprotectData failed: not this user's, or damaged (error {})", GetLastError()), kStorageWhere);
    }
    return take(out);
}

#else

result<std::vector<std::byte>> protect(std::span<const std::byte>) {
    return fail(errc::kDisabled, "DPAPI is Windows only", kStorageWhere);
}

result<std::vector<std::byte>> unprotect(std::span<const std::byte>) {
    return fail(errc::kDisabled, "DPAPI is Windows only", kStorageWhere);
}

#endif

// ---- Keychain -------------------------------------------------------------------------------------

#if defined(RHP_PLATFORM_MACOS) || defined(RHP_PLATFORM_IOS)

namespace {

struct cf_release {
    void operator()(CFTypeRef p) const noexcept {
        if (p != nullptr) {
            CFRelease(p);
        }
    }
};

template <class T>
using cf_ptr = std::unique_ptr<std::remove_pointer_t<T>, cf_release>;

[[nodiscard]] cf_ptr<CFStringRef> cf_string(std::string_view text) {
    return cf_ptr<CFStringRef>{CFStringCreateWithBytes(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(text.data()), static_cast<CFIndex>(text.size()),
                                                       kCFStringEncodingUTF8, false)};
}

// {class: generic password, service, account}: what every call matches on.
[[nodiscard]] result<cf_ptr<CFMutableDictionaryRef>> item_query(std::string_view service, std::string_view account) {
    cf_ptr<CFMutableDictionaryRef> query{CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks)};
    const auto cf_service = cf_string(service);
    const auto cf_account = cf_string(account);
    if (!query || !cf_service || !cf_account) {
        return fail(errc::kRuntime, "can't build a Keychain query", kStorageWhere);
    }
    CFDictionarySetValue(query.get(), kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(query.get(), kSecAttrService, cf_service.get());
    CFDictionarySetValue(query.get(), kSecAttrAccount, cf_account.get());
    return query;
}

[[nodiscard]] std::unexpected<error> keychain_failure(std::string_view what, OSStatus status) {
    return fail(status == errSecItemNotFound ? errc::kNotFound : errc::kRuntime, std::format("{} (OSStatus {})", what, static_cast<int>(status)), kStorageWhere);
}

} // namespace

result<std::vector<std::byte>> keychain_load(std::string_view service, std::string_view account) {
    auto query = item_query(service, account);
    if (!query) {
        return std::unexpected{std::move(query).error()};
    }
    CFDictionarySetValue(query->get(), kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(query->get(), kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef found = nullptr;
    if (const OSStatus status = SecItemCopyMatching(query->get(), &found); status != errSecSuccess) {
        return keychain_failure("no such Keychain item", status);
    }
    const cf_ptr<CFTypeRef> owned{found};
    if (CFGetTypeID(found) != CFDataGetTypeID()) {
        return fail(errc::kRuntime, "the Keychain item holds no data", kStorageWhere);
    }
    const auto data = static_cast<CFDataRef>(found);
    const auto* bytes = reinterpret_cast<const std::byte*>(CFDataGetBytePtr(data));
    return std::vector<std::byte>(bytes, bytes + CFDataGetLength(data));
}

result<void> keychain_store(std::string_view service, std::string_view account, std::span<const std::byte> secret) {
    auto query = item_query(service, account);
    if (!query) {
        return std::unexpected{std::move(query).error()};
    }
    // Replace: delete what is there (if anything), then add.
    if (const OSStatus status = SecItemDelete(query->get()); status != errSecSuccess && status != errSecItemNotFound) {
        return keychain_failure("can't replace the Keychain item", status);
    }
    const cf_ptr<CFDataRef> data{CFDataCreate(kCFAllocatorDefault, reinterpret_cast<const UInt8*>(secret.data()), static_cast<CFIndex>(secret.size()))};
    if (!data) {
        return fail(errc::kRuntime, "out of memory", kStorageWhere);
    }
    CFDictionarySetValue(query->get(), kSecValueData, data.get());
    CFDictionarySetValue(query->get(), kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
    if (const OSStatus status = SecItemAdd(query->get(), nullptr); status != errSecSuccess) {
        return keychain_failure("can't add the Keychain item", status);
    }
    return {};
}

result<void> keychain_remove(std::string_view service, std::string_view account) {
    auto query = item_query(service, account);
    if (!query) {
        return std::unexpected{std::move(query).error()};
    }
    if (const OSStatus status = SecItemDelete(query->get()); status != errSecSuccess) {
        return keychain_failure("can't remove the Keychain item", status);
    }
    return {};
}

#else

result<std::vector<std::byte>> keychain_load(std::string_view, std::string_view) {
    return fail(errc::kDisabled, "the Keychain is Apple only", kStorageWhere);
}

result<void> keychain_store(std::string_view, std::string_view, std::span<const std::byte>) {
    return fail(errc::kDisabled, "the Keychain is Apple only", kStorageWhere);
}

result<void> keychain_remove(std::string_view, std::string_view) {
    return fail(errc::kDisabled, "the Keychain is Apple only", kStorageWhere);
}

#endif

// ---- passphrases ----------------------------------------------------------------------------------

result<std::string> read_secret_line(std::string_view prompt) {
    if (!stdin_is_terminal()) {
        return fail(errc::kDisabled, "standard input is not a terminal", kStorageWhere);
    }
    std::fprintf(stderr, "%.*s", static_cast<int>(prompt.size()), prompt.data());
    std::fflush(stderr);
#if defined(RHP_PLATFORM_WINDOWS)
    const HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    const bool console = GetConsoleMode(input, &mode) != 0;
    if (console) {
        SetConsoleMode(input, mode & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    }
    const utils::scope_guard restore{[&]() noexcept {
        if (console) {
            SetConsoleMode(input, mode);
        }
    }};
#else
    termios saved{};
    const bool console = tcgetattr(STDIN_FILENO, &saved) == 0;
    if (console) {
        termios quiet = saved;
        quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }
    const utils::scope_guard restore{[&]() noexcept {
        if (console) {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
        }
    }};
#endif
    std::string line;
    const bool read = static_cast<bool>(std::getline(std::cin, line));
    std::fprintf(stderr, "\n");
    if (!read) {
        return fail(errc::kNotFound, "no passphrase (end of input)", kStorageWhere);
    }
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    return line;
}

} // namespace Rhp::platform
