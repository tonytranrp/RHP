# Layer 3: who runs what. Header-only (std::jthread); no third-party dependencies.
rhp_add_module(exec
    HEADERS
        executor.hpp
        io_runner.hpp
    DEPS
        Rhp::core
)
