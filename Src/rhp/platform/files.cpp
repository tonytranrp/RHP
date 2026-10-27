#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/random.hpp>
#include <rhp/utils/scope_guard.hpp>

#if defined(RHP_PLATFORM_WINDOWS)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <windows.h>
// After windows.h:
#include <aclapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Rhp::platform {

namespace {

std::unexpected<error> file_error(errc code, const std::filesystem::path& path, std::string_view what) {
    return fail(code, std::format("{}: {}", path.string(), what), "platform.files");
}

// Flushes `f`'s data to the device.
bool flush_to_device(std::FILE* f) noexcept {
    if (std::fflush(f) != 0) {
        return false;
    }
#if defined(RHP_PLATFORM_WINDOWS)
    return _commit(_fileno(f)) == 0;
#else
    return ::fsync(::fileno(f)) == 0;
#endif
}

unsigned long process_id() noexcept {
#if defined(RHP_PLATFORM_WINDOWS)
    return static_cast<unsigned long>(_getpid());
#else
    return static_cast<unsigned long>(::getpid());
#endif
}

#if defined(RHP_PLATFORM_WINDOWS)
// The process token's user (a TOKEN_USER in a buffer of its size); empty when it can't be read.
std::vector<std::byte> token_user() {
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == 0) {
        return {};
    }
    DWORD size = 0;
    (void)GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::byte> user(size);
    if (size == 0 || GetTokenInformation(token, TokenUser, user.data(), size, &size) == 0) {
        user.clear();
    }
    CloseHandle(token);
    return user; // moved, never copied: the TOKEN_USER points into its own buffer
}

PSID sid_of(std::vector<std::byte>& user) noexcept {
    return user.empty() ? nullptr : reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
}

// A new file only this process's user can open (a protected DACL with one ACE: no inherited ones).
std::FILE* create_owner_only(const std::filesystem::path& path) {
    auto user = token_user();
    LPWSTR sid_text = nullptr;
    if (user.empty() || ConvertSidToStringSidW(sid_of(user), &sid_text) == 0) {
        return nullptr;
    }
    const std::wstring sddl = std::wstring{L"D:P(A;;FA;;;"} + sid_text + L")";
    LocalFree(sid_text);
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr) == 0) {
        return nullptr;
    }
    SECURITY_ATTRIBUTES access{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &access, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    LocalFree(descriptor);
    if (file == INVALID_HANDLE_VALUE) {
        return nullptr;
    }
    const int fd = _open_osfhandle(reinterpret_cast<std::intptr_t>(file), _O_WRONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(file);
        return nullptr;
    }
    std::FILE* f = _fdopen(fd, "wb");
    if (f == nullptr) {
        (void)_close(fd); // closes the handle too
    }
    return f;
}
#endif

// A new file opened for writing; nullptr when it can't be made (or exists). Only its owner can read
// it on POSIX; on Windows `owner_only` gives it a DACL for this process's user alone, else it takes
// the folder's permissions.
std::FILE* create_private(const std::filesystem::path& path, [[maybe_unused]] bool owner_only) {
#if defined(RHP_PLATFORM_WINDOWS)
    if (owner_only) {
        return create_owner_only(path);
    }
    std::FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"wbx") != 0) {
        return nullptr;
    }
    return f;
#else
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return nullptr;
    }
    std::FILE* f = ::fdopen(fd, "wb");
    if (f == nullptr) {
        (void)::close(fd);
    }
    return f;
#endif
}

// Renames `from` over `to`; on Windows the rename itself is written through to the disk.
bool move_over(const std::filesystem::path& from, const std::filesystem::path& to) noexcept {
#if defined(RHP_PLATFORM_WINDOWS)
    return ::MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    return ::rename(from.c_str(), to.c_str()) == 0;
#endif
}

void sync_directory([[maybe_unused]] const std::filesystem::path& dir) noexcept {
#if !defined(RHP_PLATFORM_WINDOWS)
    const int fd = ::open(dir.c_str(), O_RDONLY);
    if (fd >= 0) {
        (void)::fsync(fd);
        (void)::close(fd);
    }
#endif
}

} // namespace

result<std::vector<std::byte>> read_file(const std::filesystem::path& path) {
    std::error_code ec;
    const bool there = std::filesystem::exists(path, ec);
    if (ec) { // can't even look (permissions, I/O): not the same as missing
        return file_error(errc::kRuntime, path, ec.message());
    }
    if (!there) {
        return file_error(errc::kNotFound, path, "no such file");
    }
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return file_error(errc::kRuntime, path, "can't open");
    }
    std::vector<std::byte> out;
    std::transform(std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}, std::back_inserter(out),
                   [](char c) { return static_cast<std::byte>(c); });
    if (in.bad()) {
        return file_error(errc::kRuntime, path, "read failed");
    }
    return out;
}

namespace {

// replace_file and write_private_file: a new temporary next to `path` (create_private), renamed over it.
result<void> write_through_temporary(const std::filesystem::path& path, std::span<const std::byte> bytes, bool owner_only) {
    // Named for this process, a random tag and the write: two writers of one folder (or a process that
    // got the pid of one that crashed mid-write) never share a temporary file.
    static std::atomic<std::uint64_t> writes{0};
    std::filesystem::path temp;
    std::FILE* f = nullptr;
    for (int attempt = 0; attempt < 4 && f == nullptr; ++attempt) {
        std::uint32_t tag = 0;
        (void)random_bytes(std::as_writable_bytes(std::span{&tag, 1}));
        temp = path;
        temp += std::format(".{}.{:08x}.{}.tmp", process_id(), tag, writes.fetch_add(1, std::memory_order_relaxed));
        f = create_private(temp, owner_only);
    }
    if (f == nullptr) {
        return file_error(errc::kRuntime, temp, "can't create");
    }
    const bool written = bytes.empty() || std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    const bool synced = written && flush_to_device(f);
    const bool closed = std::fclose(f) == 0;
    std::error_code ec;
    if (!written || !synced || !closed) {
        std::filesystem::remove(temp, ec);
        return file_error(errc::kRuntime, temp, "write failed");
    }
    if (!move_over(temp, path)) {
        std::filesystem::remove(temp, ec);
        return file_error(errc::kRuntime, path, "can't replace");
    }
    sync_directory(path.parent_path().empty() ? std::filesystem::path{"."} : path.parent_path());
    return {};
}

} // namespace

result<void> replace_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    return write_through_temporary(path, bytes, false);
}

result<void> write_private_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
    return write_through_temporary(path, bytes, true);
}

bool readable_by_others(const std::filesystem::path& path) noexcept {
#if defined(RHP_PLATFORM_WINDOWS)
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor) != ERROR_SUCCESS) {
        return false;
    }
    const utils::scope_guard free_descriptor{[descriptor]() noexcept { LocalFree(descriptor); }};
    if (dacl == nullptr) {
        return true; // no DACL: everyone may do anything
    }
    std::vector<std::byte> user;
    try {
        user = token_user();
    } catch (...) { // out of memory: judge without this process's user
    }
    const auto mine = [&](PSID sid) {
        return EqualSid(sid, owner) != 0 || (!user.empty() && EqualSid(sid, sid_of(user)) != 0) || IsWellKnownSid(sid, WinCreatorOwnerRightsSid) != 0 ||
               IsWellKnownSid(sid, WinLocalSystemSid) != 0 || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0;
    };
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* ace = nullptr;
        if (GetAce(dacl, i, &ace) == 0) {
            continue;
        }
        const auto* header = static_cast<const ACE_HEADER*>(ace);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE || (header->AceFlags & INHERIT_ONLY_ACE) != 0) {
            continue;
        }
        auto* allowed = static_cast<ACCESS_ALLOWED_ACE*>(ace);
        if ((allowed->Mask & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL)) != 0 && !mine(&allowed->SidStart)) {
            return true;
        }
    }
    return false;
#else
    std::error_code ec;
    const auto perms = std::filesystem::status(path, ec).permissions();
    return !ec && (perms & (std::filesystem::perms::group_read | std::filesystem::perms::others_read)) != std::filesystem::perms::none;
#endif
}

result<void> make_private_directory(const std::filesystem::path& path) {
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        return {};
    }
    // Every directory made here (not only the last) is its owner's.
    std::vector<std::filesystem::path> made;
    for (std::filesystem::path p = path; !p.empty() && !std::filesystem::exists(p, ec); p = p.parent_path()) {
        made.push_back(p);
        if (p == p.parent_path()) {
            break;
        }
    }
    std::filesystem::create_directories(path, ec);
    if (ec) {
        return file_error(errc::kRuntime, path, ec.message());
    }
#if !defined(RHP_PLATFORM_WINDOWS)
    for (const std::filesystem::path& p : made) {
        std::filesystem::permissions(p, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
    }
#endif
    return {};
}

void binary_stdio() noexcept {
#if defined(RHP_PLATFORM_WINDOWS)
    (void)_setmode(_fileno(stdin), _O_BINARY);
    (void)_setmode(_fileno(stdout), _O_BINARY);
#endif
}

bool stdout_is_terminal() noexcept {
#if defined(RHP_PLATFORM_WINDOWS)
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(STDOUT_FILENO) != 0;
#endif
}

bool stdin_is_terminal() noexcept {
#if defined(RHP_PLATFORM_WINDOWS)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(STDIN_FILENO) != 0;
#endif
}

bool enable_ansi_colors() noexcept {
    if (!stdout_is_terminal()) {
        return false;
    }
#if defined(RHP_PLATFORM_WINDOWS)
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (out == INVALID_HANDLE_VALUE || GetConsoleMode(out, &mode) == 0) {
        return false;
    }
    return SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    return true;
#endif
}

} // namespace Rhp::platform
