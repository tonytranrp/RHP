#include <algorithm>
#include <cstddef>
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

bool valid_key(std::string_view key) {
    if (key.empty() || key.size() > 200 || key.front() == '/' || key.back() == '/' || key.find("..") != std::string_view::npos) {
        return false;
    }
    return std::ranges::all_of(key, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '/';
    });
}

error bad_key(std::string_view key) {
    return make_error(errc::kInvalidArgument, std::format("'{}' is not a store key", key), "release.store");
}

} // namespace

// ---- memory_store ---------------------------------------------------------------------------------

result<std::vector<std::byte>> memory_store::read(std::string_view key) {
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
    for (auto it = std::filesystem::recursive_directory_iterator{dir_, ec}; !ec && it != std::filesystem::recursive_directory_iterator{}; it.increment(ec)) {
        if (!it->is_regular_file(ec) || it->path().extension() != kExtension) {
            continue;
        }
        std::string key = std::filesystem::relative(it->path(), dir_, ec).generic_string();
        key.resize(key.size() - kExtension.size());
        if (valid_key(key)) {
            out.push_back(std::move(key));
        }
    }
    if (ec) {
        return fail(errc::kRuntime, std::format("can't list {}: {}", dir_.string(), ec.message()), "release.store");
    }
    std::ranges::sort(out);
    return out;
}

} // namespace Rhp::release
