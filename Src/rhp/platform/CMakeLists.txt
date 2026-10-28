# Layer 2: the folder for general OS facts (branches on RHP_PLATFORM_*); the net/local and net/mdns
# backends branch inside their own .cpp files too.
set(rhp_platform_libs "")
if(RHP_PLATFORM STREQUAL "WINDOWS")
    list(APPEND rhp_platform_libs bcrypt advapi32 crypt32)
elseif(RHP_PLATFORM STREQUAL "MACOS" OR RHP_PLATFORM STREQUAL "IOS")
    list(APPEND rhp_platform_libs "-framework Security" "-framework CoreFoundation")
endif()

rhp_add_module(platform
    HEADERS
        files.hpp
        key_storage.hpp
        os.hpp
        process.hpp
        random.hpp
    SOURCES
        files.cpp
        key_storage.cpp
        process.cpp
        random.cpp
    DEPS
        Rhp::core
    PRIVATE_DEPS
        ${rhp_platform_libs}
)
