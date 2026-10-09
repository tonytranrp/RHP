include_guard(GLOBAL)

# rhp_monocypher: Monocypher (+ its optional Ed25519) compiled as C++ through wrapper translation units (as Lua is), so
# RHP needs no C toolchain. Only Rhp::security links it, PRIVATE, and only its .cpp files include
# monocypher.h. Upstream ships a makefile, not CMake, so the target is ours.
if(NOT DEFINED monocypher_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpMonocypher after CPMAddPackage(NAME monocypher ...)")
endif()

add_library(rhp_monocypher STATIC
    "${PROJECT_SOURCE_DIR}/cmake/monocypher/monocypher_cxx.cpp"
    "${PROJECT_SOURCE_DIR}/cmake/monocypher/monocypher_ed25519_cxx.cpp"
)
add_library(Rhp::monocypher ALIAS rhp_monocypher)
target_include_directories(rhp_monocypher SYSTEM PUBLIC "${monocypher_SOURCE_DIR}/src" "${monocypher_SOURCE_DIR}/src/optional")
target_compile_features(rhp_monocypher PUBLIC cxx_std_23)
set_target_properties(rhp_monocypher PROPERTIES FOLDER "third_party")
if(MSVC)
    target_compile_options(rhp_monocypher PRIVATE /W0)
else()
    target_compile_options(rhp_monocypher PRIVATE -w)
endif()
