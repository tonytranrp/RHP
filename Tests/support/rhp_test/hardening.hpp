#pragma once

// Tests of what some hardening levels leave out (decision AL2): they skip, saying why, in a build
// that doesn't have it, instead of failing.

#include <format>
#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <rhp/core/hardening.hpp>

namespace rhp_test {

// Skips the running test unless this build's level (RHP_HARDENING) is `most` or less strict: `what`
// (admin's io, unsigned observe code, the debugger over the wire, ...) is only there.
inline void needs(Rhp::hardening most, std::string_view what) {
    if (Rhp::kBuildHardening > most) {
        SKIP(std::format("{} needs RHP_HARDENING={} or weaker; this build is {}", what, most, Rhp::kBuildHardening));
    }
}

} // namespace rhp_test
