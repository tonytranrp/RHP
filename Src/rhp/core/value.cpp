#include <rhp/core/value.hpp>

namespace Rhp {

std::string_view to_string(value::kind k) noexcept {
    switch (k) {
    case value::kind::kNil: return "nil";
    case value::kind::kBool: return "boolean";
    case value::kind::kInteger: return "integer";
    case value::kind::kNumber: return "number";
    case value::kind::kString: return "string";
    case value::kind::kBytes: return "bytes";
    case value::kind::kArray: return "array";
    case value::kind::kMap: return "map";
    }
    return "unknown";
}

} // namespace Rhp
