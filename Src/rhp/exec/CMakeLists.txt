# Layer 3: who runs what. Header-only (std::jthread, so the system's thread library); no
# third-party dependencies.
rhp_add_module(exec
    HEADERS
        executor.hpp
        io_runner.hpp
    DEPS
        Rhp::core
        Threads::Threads
)
