include(RhpModule)

# Layer order. A module may only depend on modules added before it.
add_subdirectory(utils)   # layer 0
add_subdirectory(core)    # layer 1
add_subdirectory(script)  # layer 3

# Umbrella target: everything RHP offers, through <rhp/rhp.hpp>.
add_library(rhp INTERFACE)
add_library(Rhp::rhp ALIAS rhp)
target_sources(rhp INTERFACE
    FILE_SET HEADERS
    BASE_DIRS "${PROJECT_SOURCE_DIR}/Src"
    FILES rhp.hpp
)
target_link_libraries(rhp INTERFACE Rhp::utils Rhp::core Rhp::script)
