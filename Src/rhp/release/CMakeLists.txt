# Layer 4: signed releases (Rhp::release). Manifests, envelopes, revocation lists and stores
# build in every configuration; with RHP_ENABLE=OFF hashing and the script engine aren't there,
# so making, checking and running releases report kDisabled (release_disabled.cpp).
set(rhp_release_sources manifest.cpp store.cpp trust.cpp)
if(RHP_ENABLE)
    list(APPEND rhp_release_sources bytecode.cpp manager.cpp release.cpp)
else()
    list(APPEND rhp_release_sources release_disabled.cpp)
endif()

rhp_add_module(release
    HEADERS
        bytecode.hpp
        manager.hpp
        manifest.hpp
        release.hpp
        store.hpp
        trust.hpp
    SOURCES
        ${rhp_release_sources}
    DEPS
        Rhp::script
        Rhp::security
        Rhp::wire
        Rhp::platform
        Rhp::core
)
