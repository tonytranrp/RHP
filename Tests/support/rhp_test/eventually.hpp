#pragma once

// Waiting for another thread (a host's pump loop, a client's network thread) to get somewhere.

#include <chrono>
#include <functional>
#include <thread>

namespace rhp_test {

// True once `done()` holds, checked every `poll`; false if it still doesn't after `timeout`
// (generous: sanitizer builds are slow).
inline bool eventually(const std::function<bool()>& done, std::chrono::milliseconds timeout = std::chrono::seconds{10},
                       std::chrono::milliseconds poll = std::chrono::milliseconds{2}) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > deadline) {
            return false;
        }
        std::this_thread::sleep_for(poll);
    }
    return true;
}

} // namespace rhp_test
