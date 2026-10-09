#pragma once

#include <memory>
#include <mutex>
#include <ostream>
#include <string>

#include <rhp/core/result.hpp>
#include <rhp/event/events.hpp>

namespace Rhp::audit {

// Appends every event it is handed to a file as one JSON line (see Rhp::event::to_json), flushed
// per line so a crash loses nothing that was reported. Copies share the file; thread-safe.
//
//   auto audit = host.on_any(Rhp::audit::file_sink{"rhp_audit.log"});
//   auto exec  = host.on<Rhp::event::script_executed>(Rhp::audit::file_sink{"scripts.log"});
//
// If the file can't be opened the sink drops events; ok() says why.
class file_sink {
public:
    explicit file_sink(const std::string& path);

    void operator()(const event::any& e) const;

    template <event::host_event E>
    void operator()(const E& e) const {
        (*this)(event::any{e});
    }

    [[nodiscard]] result<void> ok() const;

private:
    struct state;
    std::shared_ptr<state> state_;
};

// The same lines to a stream the caller owns (std::clog, a test's std::ostringstream). The stream
// must outlive every copy of the sink.
class ostream_sink {
public:
    explicit ostream_sink(std::ostream& out);

    void operator()(const event::any& e) const;

    template <event::host_event E>
    void operator()(const E& e) const {
        (*this)(event::any{e});
    }

private:
    struct state;
    std::shared_ptr<state> state_;
};

} // namespace Rhp::audit
