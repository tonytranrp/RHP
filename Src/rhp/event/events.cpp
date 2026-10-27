#include <chrono>
#include <cstddef>
#include <cstdint>
#include <format>
#include <iterator>
#include <string>
#include <string_view>
#include <variant>

#include <rhp/core/error.hpp>
#include <rhp/core/role.hpp>
#include <rhp/event/events.hpp>
#include <rhp/utils/overloaded.hpp>
#include <rhp/utils/utf8.hpp>

namespace Rhp::event {

namespace {

// Builds one JSON object: {"key":value,...}.
class json_object {
public:
    explicit json_object(std::string_view event, time_point time) {
        text_ += '{';
        string("event", event);
        string("time", std::format("{:%FT%TZ}", std::chrono::floor<std::chrono::milliseconds>(time)));
    }

    json_object& string(std::string_view key, std::string_view v) {
        name(key);
        quoted(v);
        return *this;
    }

    json_object& number(std::string_view key, std::uint64_t v) {
        name(key);
        std::format_to(std::back_inserter(text_), "{}", v);
        return *this;
    }

    json_object& boolean(std::string_view key, bool v) {
        name(key);
        text_ += v ? "true" : "false";
        return *this;
    }

    // {"code":"bad_signature","message":"...","where":"..."}; kOk becomes "ok" alone.
    json_object& err(std::string_view key, const error& e) {
        name(key);
        text_ += "{\"code\":";
        quoted(to_string(e.code));
        if (e.code != errc::kOk) {
            text_ += ",\"message\":";
            quoted(e.message);
            if (!e.where.empty()) {
                text_ += ",\"where\":";
                quoted(e.where);
            }
        }
        text_ += '}';
        return *this;
    }

    [[nodiscard]] std::string done() {
        text_ += '}';
        return std::move(text_);
    }

private:
    void name(std::string_view key) {
        if (text_.size() > 1) {
            text_ += ',';
        }
        quoted(key);
        text_ += ':';
    }

    // A JSON string. Valid UTF-8 passes through; each byte of an invalid sequence becomes U+FFFD,
    // so client-supplied names can't break the line.
    void quoted(std::string_view v) {
        text_ += '"';
        for (std::size_t i = 0; i < v.size();) {
            const auto lead = static_cast<unsigned char>(v[i]);
            if (lead >= 0x80) {
                const std::size_t n = utils::utf8_sequence_length(v, i);
                if (n == 0) {
                    text_ += "\xEF\xBF\xBD"; // U+FFFD in UTF-8
                    ++i;
                } else {
                    text_.append(v.substr(i, n));
                    i += n;
                }
                continue;
            }
            const char c = v[i++];
            switch (c) {
            case '"': text_ += "\\\""; break;
            case '\\': text_ += "\\\\"; break;
            case '\n': text_ += "\\n"; break;
            case '\r': text_ += "\\r"; break;
            case '\t': text_ += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::format_to(std::back_inserter(text_), "\\u{:04x}", static_cast<unsigned>(static_cast<unsigned char>(c)));
                } else {
                    text_ += c;
                }
            }
        }
        text_ += '"';
    }

    std::string text_;
};

} // namespace

std::string to_json(const any& e) {
    return std::visit(utils::overloaded{
                          [](const session_opened& x) {
                              return json_object{x.name, x.time}
                                  .number("session", x.session.value())
                                  .string("identity", x.identity)
                                  .string("role", to_string(x.granted))
                                  .string("peer", x.peer)
                                  .string("platform", x.platform)
                                  .boolean("tls", x.tls)
                                  .done();
                          },
                          [](const session_resumed& x) {
                              return json_object{x.name, x.time}
                                  .number("session", x.session.value())
                                  .string("identity", x.identity)
                                  .string("peer", x.peer)
                                  .boolean("tls", x.tls)
                                  .done();
                          },
                          [](const session_closed& x) {
                              return json_object{x.name, x.time}
                                  .number("session", x.session.value())
                                  .string("identity", x.identity)
                                  .string("peer", x.peer)
                                  .err("reason", x.reason)
                                  .done();
                          },
                          [](const auth_failed& x) { return json_object{x.name, x.time}.string("peer", x.peer).err("reason", x.reason).done(); },
                          [](const script_executed& x) {
                              return json_object{x.name, x.time}
                                  .number("session", x.session.value())
                                  .string("identity", x.identity)
                                  .string("role", to_string(x.granted))
                                  .string("peer", x.peer)
                                  .string("op", x.op)
                                  .string("module", x.module)
                                  .string("hash", x.hash)
                                  .string("signer", x.signer)
                                  .err("outcome", x.outcome)
                                  .done();
                          },
                          [](const blob_received& x) {
                              return json_object{x.name, x.time}
                                  .number("session", x.session.value())
                                  .string("identity", x.identity)
                                  .string("sink", x.sink)
                                  .string("file", x.file)
                                  .number("size", x.size)
                                  .string("hash", x.hash)
                                  .err("outcome", x.outcome)
                                  .done();
                          },
                          [](const identity_reverted& x) {
                              return json_object{x.name, x.time}
                                  .string("identity", x.identity)
                                  .number("undone", x.undone)
                                  .number("irreversible", x.irreversible)
                                  .number("failures", x.failures)
                                  .number("pinned", x.pinned)
                                  .done();
                          },
                          [](const handler_failed& x) {
                              return json_object{x.name, x.time}
                                  .string("identity", x.identity)
                                  .string("module", x.module)
                                  .string("kind", x.kind)
                                  .string("source", x.source)
                                  .number("handler", x.handler)
                                  .string("action", x.action)
                                  .err("outcome", x.outcome)
                                  .done();
                          },
                          [](const release_changed& x) {
                              return json_object{x.name, x.time}
                                  .string("kind", x.kind)
                                  .string("channel", x.channel)
                                  .string("release", x.release)
                                  .string("fallback", x.fallback)
                                  .number("seq", x.seq)
                                  .string("reason", x.reason)
                                  .err("outcome", x.outcome)
                                  .done();
                          },
                      },
                      e);
}

} // namespace Rhp::event
