#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <rhp/build_config.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/platform/os.hpp>
#include <rhp/platform/random.hpp>

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
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace Rhp::platform {

namespace {

error file_error(errc code, const std::filesystem::path& path, std::string_view what) {
    return make_error(code, std::format("{}: {}", path.string(), what), "platform.files");
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

// A new file only its owner can read, opened for writing; nullptr when it can't be made (or exists).
std::FILE* create_private(const std::filesystem::path& path) noexcept {
#if defined(RHP_PLATFORM_WINDOWS)
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
        return std::unexpected{file_error(errc::kRuntime, path, ec.message())};
    }
    if (!there) {
        return std::unexpected{file_error(errc::kNotFound, path, "no such file")};
    }
    std::ifstream in{path, std::ios::binary};
    if (!in) {
        return std::unexpected{file_error(errc::kRuntime, path, "can't open")};
    }
    std::vector<char> chars{std::istreambuf_iterator<char>{in}, std::istreambuf_iterator<char>{}};
    if (in.bad()) {
        return std::unexpected{file_error(errc::kRuntime, path, "read failed")};
    }
    std::vector<std::byte> out(chars.size());
    for (std::size_t i = 0; i < chars.size(); ++i) {
        out[i] = static_cast<std::byte>(chars[i]);
    }
    return out;
}

result<void> replace_file(const std::filesystem::path& path, std::span<const std::byte> bytes) {
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
        f = create_private(temp);
    }
    if (f == nullptr) {
        return std::unexpected{file_error(errc::kRuntime, temp, "can't create")};
    }
    const bool written = bytes.empty() || std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    const bool synced = written && flush_to_device(f);
    const bool closed = std::fclose(f) == 0;
    std::error_code ec;
    if (!written || !synced || !closed) {
        std::filesystem::remove(temp, ec);
        return std::unexpected{file_error(errc::kRuntime, temp, "write failed")};
    }
    if (!move_over(temp, path)) {
        std::filesystem::remove(temp, ec);
        return std::unexpected{file_error(errc::kRuntime, path, "can't replace")};
    }
    sync_directory(path.parent_path().empty() ? std::filesystem::path{"."} : path.parent_path());
    return {};
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
        return std::unexpected{file_error(errc::kRuntime, path, ec.message())};
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

} // namespace Rhp::platform
