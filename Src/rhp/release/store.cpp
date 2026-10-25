#include <algorithm>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <format>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/platform/files.hpp>
#include <rhp/release/store.hpp>

namespace Rhp::release {

namespace {

constexpr std::string_view kExtension = ".rhp";

// Names Windows reserves for devices, whatever the extension ("nul.rhp" is the null device).
bool reserved_name(std::string_view segment) {
    const std::string_view stem = segment.substr(0, segment.find('.'));
    for (const std::string_view name : {"con", "prn", "aux", "nul"}) {
        if (stem == name) {
            return true;
        }
    }
    return stem.size() == 4 && (stem.starts_with("com") || stem.starts_with("lpt")) && stem[3] >= '0' && stem[3] <= '9';
}

// Lowercase segments separated by '/': no empty, "." or ".." segment, none ending in '.' (Windows
// drops the dot, so "a." would alias "a"), no device name.
bool valid_key(std::string_view key) {
    if (key.empty() || key.size() > 200) {
        return false;
    }
    if (!std::ranges::all_of(key, [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '/'; })) {
        return false;
    }
    std::size_t start = 0;
    while (start <= key.size()) {
        const std::size_t end = std::min(key.find('/', start), key.size());
        const std::string_view segment = key.substr(start, end - start);
        if (segment.empty() || segment.back() == '.' || segment.find("..") != std::string_view::npos || reserved_name(segment)) {
            return false;
        }
        start = end + 1;
    }
    return true;
}

error bad_key(std::string_view key) {
    return make_error(errc::kInvalidArgument, std::format("'{}' is not a store key", key), "release.store");
}

} // namespace

// ---- memory_store ---------------------------------------------------------------------------------

result<std::vector<std::byte>> memory_store::read(std::string_view key) {
    if (!valid_key(key)) {
        return std::unexpected{bad_key(key)};
    }
    const std::scoped_lock lock{data_->mutex};
    const auto it = data_->values.find(key);
    if (it == data_->values.end()) {
        return fail(errc::kNotFound, std::format("no '{}' stored", key), "release.store");
    }
    return it->second;
}

result<void> memory_store::write(std::string_view key, std::span<const std::byte> bytes) {
    if (!valid_key(key)) {
        return std::unexpected{bad_key(key)};
    }
    const std::scoped_lock lock{data_->mutex};
    data_->values.insert_or_assign(std::string{key}, std::vector<std::byte>(bytes.begin(), bytes.end()));
    return {};
}

result<void> memory_store::remove(std::string_view key) {
    if (!valid_key(key)) {
        return std::unexpected{bad_key(key)};
    }
    const std::scoped_lock lock{data_->mutex};
    if (const auto it = data_->values.find(key); it != data_->values.end()) {
        data_->values.erase(it);
    }
    return {};
}

result<std::vector<std::string>> memory_store::keys() {
    const std::scoped_lock lock{data_->mutex};
    std::vector<std::string> out;
    for (const auto& [k, v] : data_->values) {
        out.push_back(k);
    }
    return out;
}

// ---- directory_store ---------------------------------------------------------------------------------

result<std::filesystem::path> directory_store::path_of(std::string_view key) const {
    if (!valid_key(key)) {
        return std::unexpected{bad_key(key)};
    }
    std::filesystem::path p = dir_ / std::filesystem::path{std::string{key}};
    p += std::string{kExtension};
    return p;
}

result<std::vector<std::byte>> directory_store::read(std::string_view key) {
    auto p = path_of(key);
    if (!p) {
        return std::unexpected{std::move(p).error()};
    }
    return platform::read_file(*p);
}

result<void> directory_store::write(std::string_view key, std::span<const std::byte> bytes) {
    auto p = path_of(key);
    if (!p) {
        return std::unexpected{std::move(p).error()};
    }
    if (auto made = platform::make_private_directory(p->parent_path()); !made) {
        return made;
    }
    return platform::replace_file(*p, bytes);
}

result<void> directory_store::remove(std::string_view key) {
    auto p = path_of(key);
    if (!p) {
        return std::unexpected{std::move(p).error()};
    }
    std::error_code ec;
    std::filesystem::remove(*p, ec);
    if (ec) {
        return fail(errc::kRuntime, std::format("can't remove {}: {}", p->string(), ec.message()), "release.store");
    }
    return {};
}

result<std::vector<std::string>> directory_store::keys() {
    std::vector<std::string> out;
    std::error_code ec;
    if (!std::filesystem::is_directory(dir_, ec)) {
        return out;
    }
    const auto options = std::filesystem::directory_options::skip_permission_denied;
    for (auto it = std::filesystem::recursive_directory_iterator{dir_, options, ec}; !ec && it != std::filesystem::recursive_directory_iterator{};
         it.increment(ec)) {
        try { // one stray entry (a name the code page can't hold) is skipped, not the listing
            std::error_code entry_ec;
            if (!it->is_regular_file(entry_ec) || it->path().extension() != kExtension) {
                continue;
            }
            const std::filesystem::path relative = std::filesystem::relative(it->path(), dir_, entry_ec);
            if (entry_ec) {
                continue;
            }
            std::string key = relative.generic_string();
            if (key.size() <= kExtension.size()) {
                continue;
            }
            key.resize(key.size() - kExtension.size());
            if (valid_key(key)) {
                out.push_back(std::move(key));
            }
        } catch (const std::exception&) {
        }
    }
    if (ec) {
        return fail(errc::kRuntime, std::format("can't list {}: {}", dir_.string(), ec.message()), "release.store");
    }
    std::ranges::sort(out);
    return out;
}

} // namespace Rhp::release
