#pragma once

namespace Rhp::utils {

// std::visit(Rhp::utils::overloaded{ [](int) {}, [](const std::string&) {} }, v);
template <class... Fs>
struct overloaded : Fs... {
    using Fs::operator()...;
};

template <class... Fs>
overloaded(Fs...) -> overloaded<Fs...>;

} // namespace Rhp::utils
