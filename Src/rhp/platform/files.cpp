#include <cerrno>
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

#if defined(RHP_PLATFORM_WINDOWS)
#include <io.h>
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
    if (!std::filesystem::exists(path, ec)) {
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
    std::filesystem::path temp = path;
    temp += ".tmp";
#if defined(RHP_PLATFORM_WINDOWS)
    std::FILE* f = nullptr;
    if (_wfopen_s(&f, temp.c_str(), L"wb") != 0) {
        f = nullptr;
    }
#else
    std::FILE* f = std::fopen(temp.c_str(), "wb");
#endif
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
    std::filesystem::rename(temp, path, ec); // replaces an existing file (MoveFileExW REPLACE_EXISTING / rename(2))
    if (ec) {
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
    std::filesystem::create_directories(path, ec);
    if (ec) {
        return std::unexpected{file_error(errc::kRuntime, path, ec.message())};
    }
#if !defined(RHP_PLATFORM_WINDOWS)
    std::filesystem::permissions(path, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
#endif
    return {};
}

} // namespace Rhp::platform
