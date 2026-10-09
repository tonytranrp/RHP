# Layer 2: the only folder that branches on the target OS (RHP_PLATFORM_*).
set(rhp_platform_libs "")
if(RHP_PLATFORM STREQUAL "WINDOWS")
    list(APPEND rhp_platform_libs bcrypt)
endif()

rhp_add_module(platform
    HEADERS
        os.hpp
        random.hpp
    SOURCES
        random.cpp
    DEPS
        Rhp::core
    PRIVATE_DEPS
        ${rhp_platform_libs}
)
