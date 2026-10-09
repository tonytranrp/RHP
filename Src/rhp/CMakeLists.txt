include(RhpModule)

# Layer order. A module may only depend on modules added before it.
add_subdirectory(utils)    # layer 0
add_subdirectory(core)     # layer 1
add_subdirectory(platform) # layer 2
add_subdirectory(wire)     # layer 2
add_subdirectory(net)      # layer 3
add_subdirectory(security) # layer 3
add_subdirectory(security/tls) # layer 3
add_subdirectory(exec)     # layer 3
add_subdirectory(script)   # layer 3
add_subdirectory(event)    # layer 3
add_subdirectory(audit)    # layer 4
add_subdirectory(session)  # layer 4
add_subdirectory(config)   # layer 5
add_subdirectory(host)     # layer 5
add_subdirectory(client)   # layer 5

# Umbrella target: everything RHP offers, through <rhp/rhp.hpp>.
add_library(rhp INTERFACE)
add_library(Rhp::rhp ALIAS rhp)
target_sources(rhp INTERFACE
    FILE_SET HEADERS
    BASE_DIRS "${PROJECT_SOURCE_DIR}/Src"
    FILES rhp.hpp
)
target_link_libraries(rhp INTERFACE Rhp::utils Rhp::core Rhp::script Rhp::audit Rhp::host Rhp::client)
