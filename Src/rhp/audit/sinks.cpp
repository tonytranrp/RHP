#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>

#include <rhp/audit/sinks.hpp>
#include <rhp/core/error.hpp>
#include <rhp/core/result.hpp>
#include <rhp/event/events.hpp>

namespace Rhp::audit {

struct file_sink::state {
    std::mutex mutex;
    std::ofstream out;
    std::string path;
};

file_sink::file_sink(const std::string& path) : state_(std::make_shared<state>()) {
    state_->path = path;
    state_->out.open(path, std::ios::binary | std::ios::app);
}

void file_sink::operator()(const event::any& e) const {
    const std::string line = event::to_json(e);
    const std::scoped_lock lock{state_->mutex};
    if (state_->out) {
        state_->out << line << '\n';
        state_->out.flush();
    }
}

result<void> file_sink::ok() const {
    const std::scoped_lock lock{state_->mutex};
    if (!state_->out) {
        return fail(errc::kInvalidArgument, std::format("can't append to audit log {}", state_->path), "audit.file_sink");
    }
    return {};
}

struct ostream_sink::state {
    std::mutex mutex;
    std::ostream* out = nullptr;
};

ostream_sink::ostream_sink(std::ostream& out) : state_(std::make_shared<state>()) {
    state_->out = &out;
}

void ostream_sink::operator()(const event::any& e) const {
    const std::string line = event::to_json(e);
    const std::scoped_lock lock{state_->mutex};
    *state_->out << line << '\n';
}

} // namespace Rhp::audit
