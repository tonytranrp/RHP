#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <format>
#include <map>
#include <mutex>
#include <optional>
#include <set>

#if defined(RHP_PLATFORM_WINDOWS)
#ifndef UNICODE
#define UNICODE
#endif
#include <asio/ip/address.hpp>
#include <asio/ip/host_name.hpp>
#include <windns.h>
#include <windows.h>
#elif defined(RHP_PLATFORM_MACOS) || defined(RHP_PLATFORM_IOS)
#include <asio/io_context.hpp>
#include <asio/ip/address.hpp>
#include <asio/ip/host_name.hpp>
#include <asio/posix/stream_descriptor.hpp>
#include <dns_sd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <rhp/net/mdns/detail/metadata.hpp>
#include <rhp/net/mdns/mdns.hpp>
#include <rhp/utils/scope_guard.hpp>

namespace Rhp::net {

#if defined(RHP_PLATFORM_WINDOWS)
namespace {

std::wstring wide(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const auto n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring out(static_cast<std::size_t>(std::max(n, 0)), L'\0');
    if (n > 0) {
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), n);
    }
    return out;
}

std::string narrow(const wchar_t* text) {
    if (!text) {
        return {};
    }
    const auto n = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0 || n > 4096) {
        return {};
    }
    std::string out(static_cast<std::size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), n, nullptr, nullptr);
    out.pop_back();
    return out;
}

struct win_publication : std::enable_shared_from_this<win_publication> {
    DNS_SERVICE_INSTANCE* instance = nullptr;
    DNS_SERVICE_REGISTER_REQUEST registration{};
    DNS_SERVICE_REGISTER_REQUEST removal{};
    DNS_SERVICE_CANCEL cancel{};
    std::atomic<bool> active{true};
    std::atomic<bool> registered{false};
    std::atomic<bool> removing{false};
    std::mutex mutex;
    std::optional<error> failure;
    std::function<void(result<void>)> after_stop;
    bool stopped = false;
    ~win_publication() {
        if (instance) {
            DnsServiceFreeInstance(instance);
        }
    }

    static void WINAPI completed(DWORD status, void* context, DNS_SERVICE_INSTANCE* returned) {
        const std::unique_ptr<std::shared_ptr<win_publication>> retained{static_cast<std::shared_ptr<win_publication>*>(context)};
        auto self = *retained;
        if (returned) {
            DnsServiceFreeInstance(returned);
        }
        if (status != ERROR_SUCCESS) {
            std::function<void(result<void>)> fn;
            {
                const std::scoped_lock lock{self->mutex};
                if (self->active.load()) {
                    self->failure = make_error(errc::kTransport, std::format("DNS-SD registration failed: {}", status), "net.mdns");
                }
                self->stopped = true;
                fn = std::exchange(self->after_stop, nullptr);
            }
            if (fn) {
                fn(result<void>{});
            }
        } else {
            self->registered.store(true);
            if (!self->active.load()) {
                self->unregister();
            }
        }
    }

    static void WINAPI removed(DWORD status, void* context, DNS_SERVICE_INSTANCE* returned) {
        const std::unique_ptr<std::shared_ptr<win_publication>> retained{static_cast<std::shared_ptr<win_publication>*>(context)};
        auto self = *retained;
        if (returned) {
            DnsServiceFreeInstance(returned);
        }
        std::function<void(result<void>)> fn;
        {
            const std::scoped_lock lock{self->mutex};
            self->stopped = true;
            if (status != ERROR_SUCCESS) {
                self->failure = make_error(errc::kTransport, std::format("DNS-SD removal failed: {}", status), "net.mdns");
            }
            fn = std::exchange(self->after_stop, nullptr);
        }
        if (fn) {
            fn(status == ERROR_SUCCESS ? result<void>{} : result<void>{fail(errc::kTransport, "DNS-SD removal failed", "net.mdns")});
        }
    }

    void unregister() {
        if (removing.exchange(true)) {
            return;
        }
        removal = registration;
        removal.pRegisterCompletionCallback = &removed;
        auto retained = std::make_unique<std::shared_ptr<win_publication>>(shared_from_this());
        removal.pQueryContext = retained.get();
        const auto status = DnsServiceDeRegister(&removal, nullptr);
        if (status != DNS_REQUEST_PENDING) {
            std::function<void(result<void>)> fn;
            error err = make_error(errc::kTransport, std::format("can't remove DNS-SD registration: {}", status), "net.mdns");
            {
                const std::scoped_lock lock{mutex};
                failure = err;
                stopped = true;
                fn = std::exchange(after_stop, nullptr);
            }
            if (fn) {
                fn(std::unexpected{std::move(err)});
            }
        } else {
            (void)retained.release(); // ownership passes to the terminal native callback
        }
    }

    void stop(std::function<void(result<void>)> done = {}) {
        bool already_stopped = false;
        result<void> outcome;
        {
            const std::scoped_lock lock{mutex};
            already_stopped = stopped;
            if (already_stopped && registered.load() && failure) {
                outcome = fail(*failure);
            }
            if (!already_stopped) {
                after_stop = std::move(done);
            }
        }
        if (already_stopped) {
            if (done) {
                done(std::move(outcome));
            }
            return;
        }
        active.store(false);
        if (registered.load()) {
            unregister();
        } else {
            (void)DnsServiceRegisterCancel(&cancel);
        }
    }
};

result<std::shared_ptr<win_publication>> publish(service_record record) {
    if (record.host.empty()) {
        record.host = asio::ip::host_name() + ".local";
    }
    auto fields = detail::service_txt(record);
    if (!fields) {
        return std::unexpected{std::move(fields).error()};
    }
    const auto instance_name = wide(detail::instance_domain(record));
    const auto host = wide(record.host);
    std::vector<std::wstring> keys;
    std::vector<std::wstring> values;
    for (const auto& [key, value] : *fields) {
        keys.push_back(wide(key));
        values.push_back(wide(value));
    }
    std::vector<const wchar_t*> key_views;
    std::vector<const wchar_t*> value_views;
    for (std::size_t i = 0; i < keys.size(); ++i) {
        key_views.push_back(keys[i].c_str());
        value_views.push_back(values[i].c_str());
    }
    IP4_ADDRESS ip4{};
    IP6_ADDRESS ip6{};
    IP4_ADDRESS* v4 = nullptr;
    IP6_ADDRESS* v6 = nullptr;
    std::error_code ec;
    const auto address = asio::ip::make_address(record.address, ec);
    if (!ec && !address.is_unspecified()) {
        if (address.is_v4()) {
            const auto bytes = address.to_v4().to_bytes();
            std::memcpy(&ip4, bytes.data(), 4);
            v4 = &ip4;
        } else {
            const auto bytes = address.to_v6().to_bytes();
            std::memcpy(&ip6, bytes.data(), 16);
            v6 = &ip6;
        }
    }
    auto state = std::make_shared<win_publication>();
    state->instance = DnsServiceConstructInstance(instance_name.c_str(), host.c_str(), v4, v6, record.port, 0, 0,
                                                  static_cast<DWORD>(keys.size()), key_views.data(), value_views.data());
    if (!state->instance) {
        return fail(errc::kTransport, "can't construct DNS-SD instance", "net.mdns");
    }
    state->registration.Version = DNS_QUERY_REQUEST_VERSION1;
    state->registration.pServiceInstance = state->instance;
    state->registration.pRegisterCompletionCallback = &win_publication::completed;
    auto retained = std::make_unique<std::shared_ptr<win_publication>>(state);
    state->registration.pQueryContext = retained.get();
    const auto status = DnsServiceRegister(&state->registration, &state->cancel);
    if (status != DNS_REQUEST_PENDING) {
        return fail(errc::kTransport, std::format("can't register DNS-SD service: {}", status), "net.mdns");
    }
    (void)retained.release();
    return state;
}

class win_advertisement final : public advertisement {
    struct control {
        std::shared_ptr<io_context::poster> poster;
        std::shared_ptr<win_publication> publication;
        std::optional<error> failure;
        std::uint64_t generation = 0;
        bool active = true;
    };

public:
    win_advertisement(io_context& io, std::shared_ptr<win_publication> state) : state_(std::make_shared<control>()) {
        state_->poster = io.shared_poster();
        state_->publication = std::move(state);
    }
    ~win_advertisement() override {
        state_->active = false;
        state_->publication->stop();
    }
    result<void> update(service_record record) override {
        if (record.address != "0.0.0.0" || !record.host.empty()) {
            return fail(errc::kInvalidArgument, "native DNS-SD updates must retain the wildcard listener and default hostname", "net.mdns");
        }
        if (auto valid = detail::service_txt(record); !valid) {
            return std::unexpected{std::move(valid).error()};
        }
        const auto generation = ++state_->generation;
        state_->publication->stop([weak = std::weak_ptr<control>{state_}, poster = state_->poster, generation, record = std::move(record)](result<void> stopped) mutable {
            poster->post([weak, generation, record = std::move(record), stopped = std::move(stopped)]() mutable {
                if (auto self = weak.lock(); self && self->active && generation == self->generation) {
                    if (!stopped) {
                        self->failure = std::move(stopped).error();
                        return;
                    }
                    auto replacement = publish(std::move(record));
                    if (!replacement) {
                        self->failure = std::move(replacement).error();
                    } else {
                        self->failure.reset();
                        self->publication = std::move(*replacement);
                    }
                }
            });
        });
        return {};
    }
    [[nodiscard]] result<void> status() const override {
        if (state_->failure) {
            return fail(*state_->failure);
        }
        const std::scoped_lock lock{state_->publication->mutex};
        return state_->publication->failure ? fail(*state_->publication->failure) : result<void>{};
    }

private:
    std::shared_ptr<control> state_;
};

struct win_browse;
struct win_resolve {
    std::weak_ptr<win_browse> browser;
    std::shared_ptr<io_context::poster> poster;
    std::wstring query;
    DNS_SERVICE_RESOLVE_REQUEST request{};
    DNS_SERVICE_CANCEL cancel{};
    std::uint64_t generation = 0;
};

struct win_browse : std::enable_shared_from_this<win_browse> {
    std::shared_ptr<io_context::poster> poster;
    std::atomic<bool> active{true};
    std::wstring query;
    browse_options filter;
    DNS_SERVICE_BROWSE_REQUEST request{};
    DNS_SERVICE_CANCEL cancel{};
    std::map<std::wstring, std::shared_ptr<win_resolve>> pending;
    std::set<std::wstring> present;
    std::map<std::wstring, std::uint64_t> generations;
    std::uint64_t generation = 0;
    std::map<std::string, service_record> found;
    std::optional<error> failure;

    static void WINAPI resolved(DWORD status, void* context, DNS_SERVICE_INSTANCE* instance) {
        const std::unique_ptr<std::shared_ptr<win_resolve>> retained{static_cast<std::shared_ptr<win_resolve>*>(context)};
        auto operation = *retained;
        std::optional<service_record> record;
        if (status == ERROR_SUCCESS && instance && instance->dwPropertyCount <= 64) {
            service_record service;
            service.name = narrow(instance->pszInstanceName);
            service.name = service.name.substr(0, service.name.find('.'));
            service.host = narrow(instance->pszHostName);
            service.port = instance->wPort;
            if (instance->ip4Address) {
                asio::ip::address_v4::bytes_type bytes{};
                std::memcpy(bytes.data(), instance->ip4Address, 4);
                service.address = asio::ip::address_v4{bytes}.to_string();
            } else if (instance->ip6Address) {
                asio::ip::address_v6::bytes_type bytes{};
                std::memcpy(bytes.data(), instance->ip6Address, 16);
                const auto address = asio::ip::address_v6{bytes};
                service.address = asio::ip::address_v6{bytes, address.is_link_local() ? instance->dwInterfaceIndex : 0}.to_string();
            }
            detail::txt_fields fields;
            for (DWORD i = 0; i < instance->dwPropertyCount; ++i) {
                fields.emplace_back(narrow(instance->keys[i]), narrow(instance->values[i]));
            }
            if (auto ok = detail::read_service_txt(service, fields); ok) {
                record = std::move(service);
            }
        }
        if (instance) {
            DnsServiceFreeInstance(instance);
        }
        operation->poster->post([operation, record = std::move(record)] {
            if (auto self = operation->browser.lock(); self && self->active.load()) {
                if (auto current = self->pending.find(operation->query); current != self->pending.end() && current->second == operation) {
                    self->pending.erase(current);
                }
                if (record && self->present.contains(operation->query) && self->generations[operation->query] == operation->generation && detail::matches(*record, self->filter)) {
                    self->found[narrow(operation->query.c_str())] = *record;
                }
            }
        });
    }

    void resolve(std::wstring name) {
        if (pending.contains(name) || pending.size() >= 256) {
            return;
        }
        auto operation = std::make_shared<win_resolve>();
        operation->browser = weak_from_this();
        operation->poster = poster;
        operation->query = std::move(name);
        operation->generation = generations[operation->query];
        operation->request.Version = DNS_QUERY_REQUEST_VERSION1;
        operation->request.QueryName = operation->query.data();
        operation->request.pResolveCompletionCallback = &resolved;
        auto retained = std::make_unique<std::shared_ptr<win_resolve>>(operation);
        operation->request.pQueryContext = retained.get();
        pending.emplace(operation->query, operation);
        const auto status = DnsServiceResolve(&operation->request, &operation->cancel);
        if (status != DNS_REQUEST_PENDING) {
            pending.erase(operation->query);
        } else {
            (void)retained.release();
        }
    }

    static void WINAPI browsed(DWORD status, void* context, DNS_RECORD* records) {
        auto* retained = static_cast<std::shared_ptr<win_browse>*>(context);
        auto self = *retained;
        std::vector<std::pair<std::wstring, bool>> names;
        for (auto* r = records; r != nullptr && names.size() < 256; r = r->pNext) {
            if (r->wType == DNS_TYPE_PTR && r->Data.PTR.pNameHost) {
                names.emplace_back(r->Data.PTR.pNameHost, r->dwTtl != 0);
            }
        }
        if (records) {
            DnsRecordListFree(records, DnsFreeRecordList);
        }
        if (status == ERROR_CANCELLED) {
            const std::unique_ptr<std::shared_ptr<win_browse>> release{retained}; // terminal callback owns the native context
            return;
        }
        self->poster->post([self, status, names = std::move(names)] {
            if (!self->active.load()) {
                return;
            }
            if (status != ERROR_SUCCESS) {
                self->failure = make_error(errc::kTransport, std::format("DNS-SD browse failed: {}", status), "net.mdns");
                return;
            }
            for (const auto& [name, present] : names) {
                if (present) {
                    if (self->present.size() >= 256 && !self->present.contains(name)) {
                        continue;
                    }
                    self->present.insert(name);
                    if (!self->generations.contains(name)) {
                        self->generations[name] = ++self->generation;
                    }
                    self->resolve(name);
                } else {
                    self->present.erase(name);
                    self->generations.erase(name);
                    if (auto pending = self->pending.find(name); pending != self->pending.end()) {
                        (void)DnsServiceResolveCancel(&pending->second->cancel);
                        self->pending.erase(pending);
                    }
                    self->found.erase(narrow(name.c_str()));
                }
            }
        });
    }

    void stop() {
        if (!active.exchange(false)) {
            return;
        }
        (void)DnsServiceBrowseCancel(&cancel);
        for (auto& [name, operation] : pending) {
            (void)name;
            (void)DnsServiceResolveCancel(&operation->cancel);
        }
        pending.clear();
    }
};

class win_browser final : public discovery_browser {
public:
    explicit win_browser(std::shared_ptr<win_browse> state) : state_(std::move(state)) {}
    ~win_browser() override { state_->stop(); }
    [[nodiscard]] result<std::vector<service_record>> services() const override {
        if (state_->failure) {
            return fail(*state_->failure);
        }
        std::vector<service_record> out;
        for (const auto& [name, service] : state_->found) {
            (void)name;
            out.push_back(service);
        }
        return out;
    }

private:
    std::shared_ptr<win_browse> state_;
};

} // namespace

result<std::unique_ptr<advertisement>> mdns::advertise(io_context& io, service_record record) {
    // Windows registers services on its host records; it does not publish a
    // custom listener address. The wire responder owns those address records.
    if (record.address != "0.0.0.0" || !record.host.empty()) {
        return mdns_wire::advertise(io, std::move(record));
    }
    auto publication = publish(std::move(record));
    if (!publication) {
        return std::unexpected{std::move(publication).error()};
    }
    return std::make_unique<win_advertisement>(io, std::move(*publication));
}

result<std::unique_ptr<discovery_browser>> mdns::start_browse(io_context& io, const browse_options& options) {
    if (!detail::supported_service(options.service)) {
        return fail(errc::kInvalidArgument, "unsupported DNS-SD service type", "net.mdns");
    }
    auto state = std::make_shared<win_browse>();
    state->poster = io.shared_poster();
    state->filter = options;
    state->query = wide(options.service + ".local");
    state->request.Version = DNS_QUERY_REQUEST_VERSION1;
    state->request.QueryName = state->query.c_str();
    state->request.pBrowseCallback = &win_browse::browsed;
    auto retained = std::make_unique<std::shared_ptr<win_browse>>(state);
    state->request.pQueryContext = retained.get();
    const auto status = DnsServiceBrowse(&state->request, &state->cancel);
    if (status != DNS_REQUEST_PENDING) {
        return fail(errc::kTransport, std::format("can't browse DNS-SD services: {}", status), "net.mdns");
    }
    (void)retained.release();
    return std::make_unique<win_browser>(std::move(state));
}

#elif defined(RHP_PLATFORM_MACOS) || defined(RHP_PLATFORM_IOS)

namespace {

struct apple_operation : std::enable_shared_from_this<apple_operation> {
    DNSServiceRef ref = nullptr;
    std::unique_ptr<asio::posix::stream_descriptor> readiness;
    std::optional<error> failure;
    bool active = true;
    ~apple_operation() { stop(); }

    void stop() noexcept {
        active = false;
        if (readiness) {
            std::error_code ignored;
            readiness->close(ignored);
        }
        if (ref) {
            DNSServiceRefDeallocate(std::exchange(ref, nullptr));
        }
    }

    result<void> watch(io_context& io) {
        // Observe a duplicate: DNSServiceRef retains ownership of its original fd.
        const int fd = dup(DNSServiceRefSockFD(ref));
        if (fd < 0) {
            return fail(errc::kTransport, "can't duplicate DNS-SD descriptor", "net.mdns");
        }
        readiness = std::make_unique<asio::posix::stream_descriptor>(*static_cast<asio::io_context*>(io.native_handle()));
        std::error_code ec;
        readiness->assign(fd, ec);
        if (ec) {
            ::close(fd);
            return fail(errc::kTransport, ec.message(), "net.mdns");
        }
        wait();
        return {};
    }

    void wait() {
        readiness->async_wait(asio::posix::stream_descriptor::wait_read, [self = shared_from_this()](const std::error_code& ec) {
            if (!self->active || ec == asio::error::operation_aborted) {
                return;
            }
            if (ec) {
                self->failure = make_error(errc::kTransport, ec.message(), "net.mdns");
                return;
            }
            const auto status = DNSServiceProcessResult(self->ref);
            if (status != kDNSServiceErr_NoError) {
                self->failure = make_error(errc::kTransport, std::format("DNS-SD processing failed: {}", status), "net.mdns");
            } else if (self->active) {
                self->wait();
            }
        });
    }
};

utils::byte_buffer apple_txt(const detail::txt_fields& fields) {
    utils::byte_buffer bytes;
    for (const auto& [key, value] : fields) {
        const auto text = key + "=" + value;
        const auto length = static_cast<std::byte>(text.size());
        bytes.append({&length, 1});
        bytes.append(text);
    }
    return bytes;
}

struct apple_publication {
    std::shared_ptr<apple_operation> operation = std::make_shared<apple_operation>();
    std::shared_ptr<apple_operation> address = std::make_shared<apple_operation>();
    io_context* io = nullptr;
    service_record record;
    ~apple_publication() {
        operation->stop();
        address->stop();
    }
    static void address_registered(DNSServiceRef, DNSRecordRef, DNSServiceFlags, DNSServiceErrorType status, void* context) {
        auto& self = *static_cast<apple_publication*>(context);
        if (status != kDNSServiceErr_NoError) {
            self.operation->failure = make_error(errc::kTransport, std::format("DNS-SD address registration failed: {}", status), "net.mdns");
        }
    }
    static void registered(DNSServiceRef, DNSServiceFlags, DNSServiceErrorType status, const char*, const char*, const char*, void* context) {
        auto& self = *static_cast<apple_publication*>(context);
        if (status != kDNSServiceErr_NoError) {
            self.operation->failure = make_error(errc::kTransport, std::format("DNS-SD registration failed: {}", status), "net.mdns");
        }
    }
};

class apple_advertisement final : public advertisement {
public:
    explicit apple_advertisement(std::unique_ptr<apple_publication> state) : state_(std::move(state)) {}
    ~apple_advertisement() override { state_->operation->stop(); }
    result<void> update(service_record record) override {
        if (record.name != state_->record.name || record.port != state_->record.port || record.transport != state_->record.transport) {
            return fail(errc::kInvalidArgument, "DNS-SD update changes instance identity; create a new advertisement", "net.mdns");
        }
        if (record.host.empty()) {
            record.host = state_->record.host;
        }
        auto resolved = detail::resolve_service_record(*state_->io, std::move(record));
        if (!resolved) {
            return std::unexpected{std::move(resolved).error()};
        }
        record = std::move(*resolved);
        if (record.address != state_->record.address || record.host != state_->record.host) {
            return fail(errc::kInvalidArgument, "DNS-SD update changes the registered address", "net.mdns");
        }
        auto fields = detail::service_txt(record);
        if (!fields) {
            return std::unexpected{std::move(fields).error()};
        }
        const auto bytes = apple_txt(*fields);
        const auto status = DNSServiceUpdateRecord(state_->operation->ref, nullptr, 0, static_cast<std::uint16_t>(bytes.size()), bytes.view().data(), 0);
        if (status != kDNSServiceErr_NoError) {
            return fail(errc::kTransport, std::format("DNS-SD TXT update failed: {}", status), "net.mdns");
        }
        state_->record = std::move(record);
        return {};
    }
    [[nodiscard]] result<void> status() const override { return state_->operation->failure ? fail(*state_->operation->failure) : result<void>{}; }

private:
    std::unique_ptr<apple_publication> state_;
};

struct apple_browse;
struct apple_resolution {
    std::weak_ptr<apple_browse> browser;
    std::shared_ptr<apple_operation> operation;
    std::shared_ptr<apple_operation> addresses;
    service_record record;
    std::string key;
    std::uint32_t interface_index = 0;
    std::map<std::string, service_record> live_addresses;
};

struct apple_browse : std::enable_shared_from_this<apple_browse> {
    explicit apple_browse(io_context& context) : io(context) {}
    io_context& io;
    browse_options filter;
    std::shared_ptr<apple_operation> operation = std::make_shared<apple_operation>();
    std::map<std::string, std::shared_ptr<apple_resolution>> pending;
    std::map<std::string, service_record> found;

    static void addressed(DNSServiceRef, DNSServiceFlags flags, std::uint32_t interface_index, DNSServiceErrorType status, const char*, const sockaddr* address,
                          std::uint32_t, void* context) {
        auto& resolution = *static_cast<apple_resolution*>(context);
        auto self = resolution.browser.lock();
        if (!self || status != kDNSServiceErr_NoError || !address) {
            return;
        }
        auto record = resolution.record;
        if (address->sa_family == AF_INET) {
            asio::ip::address_v4::bytes_type bytes{};
            std::memcpy(bytes.data(), &reinterpret_cast<const sockaddr_in*>(address)->sin_addr, 4);
            record.address = asio::ip::address_v4{bytes}.to_string();
        } else if (address->sa_family == AF_INET6) {
            const auto* v6 = reinterpret_cast<const sockaddr_in6*>(address);
            asio::ip::address_v6::bytes_type bytes{};
            std::memcpy(bytes.data(), &v6->sin6_addr, 16);
            auto ip = asio::ip::address_v6{bytes, v6->sin6_scope_id};
            if (ip.is_link_local() && ip.scope_id() == 0) {
                ip.scope_id(interface_index);
                if (ip.scope_id() == 0) {
                    return;
                }
            }
            record.address = ip.to_string();
        }
        if ((flags & kDNSServiceFlagsAdd) == 0) {
            resolution.live_addresses.erase(record.address);
        } else if (record.port != 0 && !record.address.empty() && detail::matches(record, self->filter)) {
            resolution.live_addresses[record.address] = std::move(record);
        }
        self->found.erase(resolution.key);
        if (!resolution.live_addresses.empty()) {
            const auto v4 = std::ranges::find_if(resolution.live_addresses, [](const auto& entry) { return entry.first.find(':') == std::string::npos; });
            self->found[resolution.key] = (v4 == resolution.live_addresses.end() ? resolution.live_addresses.begin() : v4)->second;
        }
    }

    static void resolved(DNSServiceRef, DNSServiceFlags, std::uint32_t interface_index, DNSServiceErrorType status, const char*, const char* host,
                         std::uint16_t port, std::uint16_t txt_length, const unsigned char* txt, void* context) {
        auto& resolution = *static_cast<apple_resolution*>(context);
        auto self = resolution.browser.lock();
        if (!self || status != kDNSServiceErr_NoError || !host) {
            return;
        }
        resolution.record.host = host;
        resolution.record.port = ntohs(port);
        detail::txt_fields fields;
        const auto count = TXTRecordGetCount(txt_length, txt);
        if (count > 64) {
            return;
        }
        for (std::uint16_t i = 0; i < count; ++i) {
            std::array<char, 256> key{};
            std::uint8_t length = 0;
            const void* data = nullptr;
            if (TXTRecordGetItemAtIndex(txt_length, txt, i, static_cast<std::uint16_t>(key.size()), key.data(), &length, &data) != kDNSServiceErr_NoError) {
                return;
            }
            fields.emplace_back(key.data(), data ? std::string{static_cast<const char*>(data), length} : std::string{});
        }
        // TXT validation also checks endpoint completeness; the actual address follows.
        resolution.record.address = "pending";
        self->found.erase(resolution.key);
        resolution.live_addresses.clear();
        if (auto ok = detail::read_service_txt(resolution.record, fields); !ok) {
            return;
        }
        resolution.record.address.clear();
        if (resolution.addresses) {
            resolution.addresses->stop();
        }
        resolution.addresses = std::make_shared<apple_operation>();
        const auto result = DNSServiceGetAddrInfo(&resolution.addresses->ref, 0, interface_index, kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6,
                                                  host, &addressed, &resolution);
        if (result == kDNSServiceErr_NoError) {
            if (auto ok = resolution.addresses->watch(self->io); !ok) {
                resolution.addresses->failure = std::move(ok).error();
            }
        }
    }

    static void browsed(DNSServiceRef, DNSServiceFlags flags, std::uint32_t interface_index, DNSServiceErrorType status, const char* name,
                        const char* type, const char* domain, void* context) {
        auto& self = *static_cast<apple_browse*>(context);
        if (status != kDNSServiceErr_NoError || !name || !type || !domain) {
            if (status != kDNSServiceErr_NoError) {
                self.operation->failure = make_error(errc::kTransport, std::format("DNS-SD browse failed: {}", status), "net.mdns");
            }
            return;
        }
        const auto key = std::format("{}:{}:{}:{}", name, type, domain, interface_index);
        if ((flags & kDNSServiceFlagsAdd) == 0) {
            if (auto it = self.pending.find(key); it != self.pending.end()) {
                it->second->operation->stop();
                if (it->second->addresses) {
                    it->second->addresses->stop();
                }
                self.pending.erase(it);
            }
            self.found.erase(key);
            return;
        }
        if (self.pending.contains(key) || self.pending.size() >= 256) {
            return;
        }
        auto resolution = std::make_shared<apple_resolution>();
        resolution->browser = self.weak_from_this();
        resolution->key = key;
        resolution->record.name = name;
        resolution->interface_index = interface_index;
        resolution->operation = std::make_shared<apple_operation>();
        const auto result = DNSServiceResolve(&resolution->operation->ref, 0, interface_index, name, type, domain, &resolved, resolution.get());
        if (result == kDNSServiceErr_NoError) {
            self.pending[key] = resolution;
            if (auto ok = resolution->operation->watch(self.io); !ok) {
                resolution->operation->failure = std::move(ok).error();
            }
        }
    }

    void stop() {
        operation->stop();
        for (auto& [key, resolution] : pending) {
            (void)key;
            resolution->operation->stop();
            if (resolution->addresses) {
                resolution->addresses->stop();
            }
        }
        pending.clear();
    }
};

class apple_browser final : public discovery_browser {
public:
    explicit apple_browser(std::shared_ptr<apple_browse> state) : state_(std::move(state)) {}
    ~apple_browser() override { state_->stop(); }
    [[nodiscard]] result<std::vector<service_record>> services() const override {
        if (state_->operation->failure) {
            return fail(*state_->operation->failure);
        }
        std::vector<service_record> out;
        for (const auto& [key, record] : state_->found) {
            (void)key;
            out.push_back(record);
        }
        return out;
    }

private:
    std::shared_ptr<apple_browse> state_;
};

} // namespace

result<std::unique_ptr<advertisement>> mdns::advertise(io_context& io, service_record record) {
    auto resolved = detail::resolve_service_record(io, std::move(record));
    if (!resolved) {
        return std::unexpected{std::move(resolved).error()};
    }
    record = std::move(*resolved);
    auto fields = detail::service_txt(record);
    if (!fields) {
        return std::unexpected{std::move(fields).error()};
    }
    const auto txt = apple_txt(*fields);
    auto state = std::make_unique<apple_publication>();
    state->io = &io;
    state->record = record;
    std::error_code ec;
    const auto address = asio::ip::make_address(record.address, ec);
    std::uint32_t interface = kDNSServiceInterfaceIndexLocalOnly;
    if (!address.is_loopback()) {
        interface = 0;
        ifaddrs* addresses = nullptr;
        if (getifaddrs(&addresses) != 0) {
            return fail(errc::kTransport, "can't enumerate discovery interfaces", "net.mdns");
        }
        const utils::scope_guard release{[&] { freeifaddrs(addresses); }};
        for (auto* item = addresses; item; item = item->ifa_next) {
            if (!item->ifa_addr || (item->ifa_flags & IFF_UP) == 0) {
                continue;
            }
            // getifaddrs exposes the sockaddr layout selected by sa_family.
            if (address.is_v4() && item->ifa_addr->sa_family == AF_INET) {
                const auto* endpoint = reinterpret_cast<const sockaddr_in*>(item->ifa_addr);
                const auto bytes = address.to_v4().to_bytes();
                if (std::memcmp(&endpoint->sin_addr, bytes.data(), bytes.size()) == 0) {
                    interface = if_nametoindex(item->ifa_name);
                    break;
                }
            } else if (address.is_v6() && item->ifa_addr->sa_family == AF_INET6) {
                const auto* endpoint = reinterpret_cast<const sockaddr_in6*>(item->ifa_addr);
                const auto bytes = address.to_v6().to_bytes();
                if (std::memcmp(&endpoint->sin6_addr, bytes.data(), bytes.size()) == 0 &&
                    (address.to_v6().scope_id() == 0 || address.to_v6().scope_id() == if_nametoindex(item->ifa_name))) {
                    interface = if_nametoindex(item->ifa_name);
                    break;
                }
            }
        }
        if (interface == 0) {
            return fail(errc::kInvalidArgument, "discovery address is not on a local interface", "net.mdns");
        }
    }
    auto host = record.host;
    if (!host.ends_with('.')) {
        host += '.';
    }
    auto status = DNSServiceCreateConnection(&state->address->ref);
    if (status != kDNSServiceErr_NoError) {
        return fail(errc::kTransport, std::format("can't create DNS-SD address connection: {}", status), "net.mdns");
    }
    utils::byte_buffer address_bytes;
    if (address.is_v4()) {
        const auto bytes = address.to_v4().to_bytes();
        address_bytes.append(std::as_bytes(std::span{bytes}));
    } else {
        const auto bytes = address.to_v6().to_bytes();
        address_bytes.append(std::as_bytes(std::span{bytes}));
    }
    DNSRecordRef address_record = nullptr;
    status = DNSServiceRegisterRecord(state->address->ref, &address_record, kDNSServiceFlagsUnique, interface, host.c_str(),
                                      address.is_v4() ? kDNSServiceType_A : kDNSServiceType_AAAA, kDNSServiceClass_IN,
                                      static_cast<std::uint16_t>(address_bytes.size()), address_bytes.view().data(), 0,
                                      &apple_publication::address_registered, state.get());
    if (status != kDNSServiceErr_NoError) {
        return fail(errc::kTransport, std::format("can't register DNS-SD address: {}", status), "net.mdns");
    }
    if (auto ok = state->address->watch(io); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    const std::string type{detail::service_type(record.transport)};
    status = DNSServiceRegister(&state->operation->ref, kDNSServiceFlagsNoAutoRename, interface, record.name.c_str(), type.c_str(), nullptr, host.c_str(),
                                htons(record.port), static_cast<std::uint16_t>(txt.size()), txt.view().data(), &apple_publication::registered, state.get());
    if (status != kDNSServiceErr_NoError) {
        return fail(errc::kTransport, std::format("can't register DNS-SD service: {}", status), "net.mdns");
    }
    if (auto ok = state->operation->watch(io); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return std::make_unique<apple_advertisement>(std::move(state));
}

result<std::unique_ptr<discovery_browser>> mdns::start_browse(io_context& io, const browse_options& options) {
    if (!detail::supported_service(options.service)) {
        return fail(errc::kInvalidArgument, "unsupported DNS-SD service type", "net.mdns");
    }
    auto state = std::make_shared<apple_browse>(io);
    state->filter = options;
    const auto status = DNSServiceBrowse(&state->operation->ref, 0, 0, options.service.c_str(), nullptr, &apple_browse::browsed, state.get());
    if (status != kDNSServiceErr_NoError) {
        return fail(errc::kTransport, std::format("can't browse DNS-SD services: {}", status), "net.mdns");
    }
    if (auto ok = state->operation->watch(io); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
    return std::make_unique<apple_browser>(std::move(state));
}

#else

result<std::unique_ptr<advertisement>> mdns::advertise(io_context& io, service_record record) {
    return mdns_wire::advertise(io, std::move(record));
}

result<std::unique_ptr<discovery_browser>> mdns::start_browse(io_context& io, const browse_options& options) {
    return mdns_wire::start_browse(io, options);
}

#endif

} // namespace Rhp::net
