#pragma once

#include <concepts>
#include <cstddef>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>

namespace Rhp::release {

// Where a release manager keeps what must survive a restart: the channel state, the revocation
// list and the envelopes of the releases it may run again. Keys are short paths of [a-z0-9._-/]
// ("state", "revocations", "releases/<hex id>"). read() of a missing key is kNotFound; write()
// replaces a value as a whole (a crash leaves the old value or the new one).
//
//   struct S {
//       result<std::vector<std::byte>> read(std::string_view key);
//       result<void> write(std::string_view key, std::span<const std::byte> bytes);
//       result<void> remove(std::string_view key);             // a missing key is fine
//       result<std::vector<std::string>> keys();                // every key it holds
//   };
template <class S>
concept storage = requires(S& s, std::string_view key, std::span<const std::byte> bytes) {
    { s.read(key) } -> std::same_as<result<std::vector<std::byte>>>;
    { s.write(key, bytes) } -> std::same_as<result<void>>;
    { s.remove(key) } -> std::same_as<result<void>>;
    { s.keys() } -> std::same_as<result<std::vector<std::string>>>;
};

// A storage held behind one interface (the manager compiles once). Owns what it was given. An empty
// one (default-constructed) holds none: every call reports kInvalidArgument.
class any_store {
public:
    any_store() = default;

    template <storage S>
        requires(!std::same_as<std::remove_cvref_t<S>, any_store>)
    any_store(S s) : self_(std::make_shared<model<S>>(std::move(s))) {} // implicit: anything that is a storage converts

    [[nodiscard]] explicit operator bool() const noexcept { return self_ != nullptr; }
    [[nodiscard]] result<std::vector<std::byte>> read(std::string_view key) const {
        if (!self_) {
            return no_store();
        }
        return self_->read(key);
    }
    [[nodiscard]] result<void> write(std::string_view key, std::span<const std::byte> bytes) const {
        if (!self_) {
            return no_store();
        }
        return self_->write(key, bytes);
    }
    [[nodiscard]] result<void> remove(std::string_view key) const {
        if (!self_) {
            return no_store();
        }
        return self_->remove(key);
    }
    [[nodiscard]] result<std::vector<std::string>> keys() const {
        if (!self_) {
            return no_store();
        }
        return self_->keys();
    }

private:
    [[nodiscard]] static std::unexpected<error> no_store() { return fail(errc::kInvalidArgument, "this any_store holds no storage", "release.store"); }

    struct concept_t {
        virtual ~concept_t() = default;
        virtual result<std::vector<std::byte>> read(std::string_view key) = 0;
        virtual result<void> write(std::string_view key, std::span<const std::byte> bytes) = 0;
        virtual result<void> remove(std::string_view key) = 0;
        virtual result<std::vector<std::string>> keys() = 0;
    };

    template <class S>
    struct model final : concept_t {
        explicit model(S s) : store(std::move(s)) {}
        result<std::vector<std::byte>> read(std::string_view key) override { return store.read(key); }
        result<void> write(std::string_view key, std::span<const std::byte> bytes) override { return store.write(key, bytes); }
        result<void> remove(std::string_view key) override { return store.remove(key); }
        result<std::vector<std::string>> keys() override { return store.keys(); }
        S store;
    };

    std::shared_ptr<concept_t> self_;
};

// Nothing survives the process: for tests and for hosts that only want rollout, not persistence.
// Copies share one map.
class memory_store {
public:
    [[nodiscard]] result<std::vector<std::byte>> read(std::string_view key);
    [[nodiscard]] result<void> write(std::string_view key, std::span<const std::byte> bytes);
    [[nodiscard]] result<void> remove(std::string_view key);
    [[nodiscard]] result<std::vector<std::string>> keys();

private:
    struct shared {
        std::mutex mutex;
        std::map<std::string, std::vector<std::byte>, std::less<>> values;
    };
    std::shared_ptr<shared> data_ = std::make_shared<shared>();
};

// One file per key under a directory (created on first write, owner-only on POSIX): "state"
// becomes <dir>/state.rhp, "releases/ab12..." <dir>/releases/ab12....rhp. Writes go through
// platform::replace_file (synced, then renamed into place).
class directory_store {
public:
    explicit directory_store(std::filesystem::path dir) : dir_(std::move(dir)) {}

    [[nodiscard]] result<std::vector<std::byte>> read(std::string_view key);
    [[nodiscard]] result<void> write(std::string_view key, std::span<const std::byte> bytes);
    [[nodiscard]] result<void> remove(std::string_view key);
    [[nodiscard]] result<std::vector<std::string>> keys();

    [[nodiscard]] const std::filesystem::path& directory() const noexcept { return dir_; }

private:
    [[nodiscard]] result<std::filesystem::path> path_of(std::string_view key) const;

    std::filesystem::path dir_;
};

static_assert(storage<memory_store>);
static_assert(storage<directory_store>);

} // namespace Rhp::release
