#pragma once

#include <rhp/host/detail/engine.hpp>
#include <rhp/release/manager.hpp>
#include <rhp/wire/messages.hpp>

namespace Rhp::host_detail {

// Answers the release requests of a host's sessions with `releases` (host/releases.cpp).
[[nodiscard]] release_bridge bridge(release::manager& releases);

// The wire form of a manager's status.
[[nodiscard]] wire::release_status_reply to_message(const release::manager& releases);

} // namespace Rhp::host_detail
