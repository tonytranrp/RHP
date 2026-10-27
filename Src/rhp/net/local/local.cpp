#include <chrono>
#include <cstddef>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>

#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#if defined(RHP_PLATFORM_WINDOWS)
#include <asio/windows/overlapped_ptr.hpp>
#include <asio/windows/stream_handle.hpp>
#include <sddl.h>
#else
#include <asio/local/stream_protocol.hpp>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <rhp/net/detail/asio_support.hpp>
#include <rhp/net/local/local.hpp>

namespace Rhp::net {

namespace {

#if defined(RHP_PLATFORM_WINDOWS)
using stream = asio::windows::stream_handle;
#else
using stream = asio::local::stream_protocol::socket;
#endif

using detail::context_of;

result<void> check_endpoint(const endpoint& ep) {
    if (ep.port != 0 || ep.host.empty() || ep.host.find('\0') != std::string::npos) {
        return fail(errc::kInvalidArgument, "IPC needs a nonempty name and port zero", "net.local_ipc");
    }
#if defined(RHP_PLATFORM_WINDOWS)
    if (ep.host.size() > 200 || ep.host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-") != std::string::npos) {
        return fail(errc::kInvalidArgument, "pipe name must contain only letters, digits, dot, underscore or dash", "net.local_ipc");
    }
#else
#if defined(RHP_PLATFORM_LINUX) || defined(RHP_PLATFORM_ANDROID)
    if (ep.host.starts_with('@')) {
        return ep.host.size() > 1 ? result<void>{} : result<void>{fail(errc::kInvalidArgument, "abstract IPC needs a name after @", "net.local_ipc")};
    }
#endif
    if (!std::filesystem::path{ep.host}.is_absolute()) {
        return fail(errc::kInvalidArgument, "IPC socket path must be absolute", "net.local_ipc");
    }
#endif
    return {};
}

struct ipc_traits {
    static error read_error(const std::error_code& ec, const std::string& peer) { return make_error(errc::kTransport, ec.message(), peer); }
    static void before_close(stream&) noexcept {}
};

// The other end is always on this machine.
[[nodiscard]] std::unique_ptr<link> make_link(stream socket, std::string name) {
    return std::make_unique<detail::stream_link<stream, ipc_traits>>(std::move(socket), std::move(name), true);
}

#if defined(RHP_PLATFORM_WINDOWS)

std::wstring pipe_path(std::string_view name) {
    return L"\\\\.\\pipe\\rhp." + std::wstring{name.begin(), name.end()};
}

result<stream> make_pipe(io_context& io, const std::string& name, bool first) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;OW)", SDDL_REVISION_1, &descriptor, nullptr)) {
        return fail(errc::kTransport, "can't create pipe access control", "net.local_ipc");
    }
    SECURITY_ATTRIBUTES access{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    const HANDLE pipe = CreateNamedPipeW(pipe_path(name).c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
                                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, &access);
    const auto status = GetLastError();
    LocalFree(descriptor);
    if (pipe == INVALID_HANDLE_VALUE) {
        return fail(errc::kTransport, std::format("CreateNamedPipe failed: {}", status), name);
    }
    std::error_code ec;
    stream socket{context_of(io)};
    socket.assign(pipe, ec);
    if (ec) {
        CloseHandle(pipe);
        return fail(errc::kTransport, ec.message(), name);
    }
    return socket;
}

struct listener_state : std::enable_shared_from_this<listener_state> {
    listener_state(io_context& context, std::string pipe) : io(context), name(std::move(pipe)), retry(context_of(context)) {}
    io_context& io;
    std::string name;
    std::unique_ptr<stream> pending;
    accept_fn accepted;
    asio::steady_timer retry;
    bool open = true;

    void replenish() {
        if (!open) {
            return;
        }
        auto next = make_pipe(io, name, false);
        if (next) {
            pending = std::make_unique<stream>(std::move(*next));
            accept();
        } else {
            retry.expires_after(std::chrono::milliseconds{100});
            retry.async_wait([weak = weak_from_this()](const std::error_code& ec) {
                if (auto self = weak.lock(); self && !ec) {
                    self->replenish();
                }
            });
        }
    }

    void accept() {
        asio::windows::overlapped_ptr op(context_of(io), [self = shared_from_this()](const std::error_code& ec, std::size_t) {
            if (!self->open) {
                return;
            }
            auto connected = std::move(self->pending);
            self->replenish();
            if (!ec) {
                self->accepted(make_link(std::move(*connected), "pipe:" + self->name));
            }
        });
        if (ConnectNamedPipe(pending->native_handle(), op.get()) != FALSE) {
            op.release(); // successful overlapped call already queues its IOCP completion
        } else {
            const auto status = GetLastError();
            if (status == ERROR_IO_PENDING) {
                op.release();
            } else {
                op.complete(status == ERROR_PIPE_CONNECTED ? std::error_code{} : std::error_code{static_cast<int>(status), std::system_category()}, 0);
            }
        }
    }
};

struct dial_state : std::enable_shared_from_this<dial_state> {
    dial_state(io_context& context, std::string pipe, connect_fn fn) : io(context), name(std::move(pipe)), connected(std::move(fn)), retry(context_of(context)) {}
    io_context& io;
    std::string name;
    connect_fn connected;
    asio::steady_timer retry;
    std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};

    void dial() {
        // SECURITY_IDENTIFICATION: whoever owns the pipe may learn who we are but can't impersonate
        // us (the default for pipe clients is full impersonation).
        const HANDLE pipe = CreateFileW(pipe_path(name).c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            const auto status = GetLastError();
            if (status == ERROR_PIPE_BUSY && std::chrono::steady_clock::now() < deadline) {
                retry.expires_after(std::chrono::milliseconds{20});
                retry.async_wait([self = shared_from_this()](const std::error_code& ec) {
                    if (!ec) {
                        self->dial();
                    }
                });
            } else {
                connected(fail(errc::kTransport, std::format("CreateFile(pipe) failed: {}", status), name));
            }
            return;
        }
        stream socket{context_of(io)};
        std::error_code ec;
        socket.assign(pipe, ec);
        if (ec) {
            CloseHandle(pipe);
            connected(fail(errc::kTransport, ec.message(), name));
        } else {
            connected(make_link(std::move(socket), "pipe:" + name));
        }
    }
};

#else

std::string socket_name(std::string_view name) {
    std::string out{name};
#if defined(RHP_PLATFORM_LINUX) || defined(RHP_PLATFORM_ANDROID)
    if (out.starts_with('@')) {
        out.front() = '\0'; // Linux's abstract namespace; Asio retains the full string length
    }
#endif
    return out;
}

// The kernel's word on who is at the other end. Abstract names have no file mode to protect them, so
// the UID check is their only access control; pathname sockets get it as a second line behind 0600.
bool allowed_peer(stream& socket) {
#if defined(RHP_PLATFORM_LINUX) || defined(RHP_PLATFORM_ANDROID)
    ucred credentials{};
    socklen_t bytes = sizeof(credentials);
    return getsockopt(socket.native_handle(), SOL_SOCKET, SO_PEERCRED, &credentials, &bytes) == 0 && bytes == sizeof(credentials) && credentials.uid == geteuid();
#else
    (void)socket;
    return true; // Apple: the 0600 socket mode and the app's private directory
#endif
}

struct listener_state : std::enable_shared_from_this<listener_state> {
    explicit listener_state(io_context& io) : acceptor(context_of(io)) {}
    asio::local::stream_protocol::acceptor acceptor;
    std::string path;
    accept_fn accepted;
    bool open = true;
    dev_t device = 0;
    ino_t inode = 0;

    void accept() {
        acceptor.async_accept([self = shared_from_this()](const std::error_code& ec, stream socket) {
            if (!self->open) {
                return;
            }
            if (!ec && allowed_peer(socket)) {
                self->accepted(make_link(std::move(socket), "unix:" + self->path));
            }
            if (self->open) {
                self->accept();
            }
        });
    }

    void unlink_owned() noexcept {
        struct stat st{};
        if (inode != 0 && lstat(path.c_str(), &st) == 0 && st.st_dev == device && st.st_ino == inode && S_ISSOCK(st.st_mode)) {
            (void)unlink(path.c_str());
        }
        inode = 0;
    }
    ~listener_state() { unlink_owned(); }
};

#endif

class local_listener final : public listener {
public:
    explicit local_listener(std::shared_ptr<listener_state> state) : state_(std::move(state)) {}
    ~local_listener() override {
        state_->open = false;
        state_->accepted = nullptr;
        std::error_code ignored;
#if defined(RHP_PLATFORM_WINDOWS)
        state_->retry.cancel();
        if (state_->pending) {
            state_->pending->close(ignored);
        }
#else
        state_->acceptor.close(ignored);
        state_->unlink_owned();
#endif
    }
    [[nodiscard]] unsigned short port() const noexcept override { return 0; }

private:
    std::shared_ptr<listener_state> state_;
};

} // namespace

result<std::unique_ptr<listener>> local_ipc::listen(io_context& io, const endpoint& ep, accept_fn on_accept) {
    if (auto ok = check_endpoint(ep); !ok) {
        return std::unexpected{std::move(ok).error()};
    }
#if defined(RHP_PLATFORM_WINDOWS)
    auto pipe = make_pipe(io, ep.host, true);
    if (!pipe) {
        return std::unexpected{std::move(pipe).error()};
    }
    auto state = std::make_shared<listener_state>(io, ep.host);
    state->pending = std::make_unique<stream>(std::move(*pipe));
#else
    auto state = std::make_shared<listener_state>(io);
    state->path = ep.host;
    std::error_code ec;
    try {
        state->acceptor.open(asio::local::stream_protocol{}, ec);
        if (!ec) {
            state->acceptor.bind(asio::local::stream_protocol::endpoint{socket_name(ep.host)}, ec);
        }
    } catch (const std::system_error& e) {
        ec = e.code();
    }
    if (ec) {
        return fail(errc::kTransport, ec.message(), ep.host);
    }
    if (!ep.host.starts_with('@')) {
        struct stat st{};
        if (lstat(ep.host.c_str(), &st) != 0) {
            return fail(errc::kTransport, "can't identify IPC socket path", ep.host);
        }
        state->device = st.st_dev;
        state->inode = st.st_ino;
        if (chmod(ep.host.c_str(), S_IRUSR | S_IWUSR) != 0) {
            return fail(errc::kTransport, "can't secure IPC socket path", ep.host);
        }
    }
    state->acceptor.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        return fail(errc::kTransport, ec.message(), ep.host);
    }
#endif
    state->accepted = std::move(on_accept);
    state->accept();
    return std::make_unique<local_listener>(std::move(state));
}

void local_ipc::dial(io_context& io, const endpoint& ep, connect_fn on_connect) {
    if (auto ok = check_endpoint(ep); !ok) {
        io.post([fn = std::move(on_connect), err = std::move(ok).error()]() mutable { fn(std::unexpected{std::move(err)}); });
        return;
    }
#if defined(RHP_PLATFORM_WINDOWS)
    auto state = std::make_shared<dial_state>(io, ep.host, std::move(on_connect));
    io.post([state] { state->dial(); });
#else
    auto socket = std::make_shared<stream>(context_of(io));
    std::optional<asio::local::stream_protocol::endpoint> address;
    try {
        address.emplace(socket_name(ep.host));
    } catch (const std::system_error& e) {
        io.post([fn = std::move(on_connect), err = make_error(errc::kTransport, e.what(), ep.host)]() mutable { fn(std::unexpected{std::move(err)}); });
        return;
    }
    socket->async_connect(*address, [socket, fn = std::move(on_connect), path = ep.host](const std::error_code& ec) mutable {
        if (ec) {
            fn(fail(errc::kTransport, ec.message(), path));
        } else if (!allowed_peer(*socket)) {
            fn(fail(errc::kForbidden, "the IPC listener runs as another user", path));
        } else {
            fn(make_link(std::move(*socket), "unix:" + path));
        }
    });
#endif
}

} // namespace Rhp::net
