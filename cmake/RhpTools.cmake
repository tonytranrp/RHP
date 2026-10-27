include_guard(GLOBAL)

# Third-party targets for Tools/ (rhp-cli) only: CLI11 (header-only) and replxx (line editing).
# Both are SYSTEM so their headers stay out of RHP's warnings-as-errors build; replxx is built by
# our own target (its CMakeLists globs sources and sets flags we don't want) and keeps upstream's
# warning-free compiler defaults.
if(NOT DEFINED CLI11_SOURCE_DIR OR NOT DEFINED replxx_SOURCE_DIR)
    message(FATAL_ERROR "RHP: include RhpTools after CPMAddPackage(NAME CLI11 ...) and (NAME replxx ...)")
endif()

add_library(rhp_cli11 INTERFACE)
add_library(Rhp::cli11 ALIAS rhp_cli11)
target_include_directories(rhp_cli11 SYSTEM INTERFACE "${CLI11_SOURCE_DIR}/include")
target_compile_features(rhp_cli11 INTERFACE cxx_std_23)

add_library(rhp_replxx STATIC
    "${replxx_SOURCE_DIR}/src/ConvertUTF.cpp"
    "${replxx_SOURCE_DIR}/src/conversion.cxx"
    "${replxx_SOURCE_DIR}/src/escape.cxx"
    "${replxx_SOURCE_DIR}/src/history.cxx"
    "${replxx_SOURCE_DIR}/src/prompt.cxx"
    "${replxx_SOURCE_DIR}/src/replxx.cxx"
    "${replxx_SOURCE_DIR}/src/replxx_impl.cxx"
    "${replxx_SOURCE_DIR}/src/terminal.cxx"
    "${replxx_SOURCE_DIR}/src/util.cxx"
    "${replxx_SOURCE_DIR}/src/wcwidth.cpp"
    "${replxx_SOURCE_DIR}/src/windows.cxx"
)
add_library(Rhp::replxx ALIAS rhp_replxx)
target_include_directories(rhp_replxx SYSTEM PUBLIC "${replxx_SOURCE_DIR}/include")
target_include_directories(rhp_replxx PRIVATE "${replxx_SOURCE_DIR}/src")
target_compile_definitions(rhp_replxx PUBLIC REPLXX_STATIC)
target_compile_features(rhp_replxx PUBLIC cxx_std_23)
target_link_libraries(rhp_replxx PUBLIC Threads::Threads)
set_target_properties(rhp_replxx PROPERTIES FOLDER "third_party")
if(MSVC)
    target_compile_definitions(rhp_replxx PRIVATE _CRT_SECURE_NO_WARNINGS=1)
endif()
rhp_third_party_flags(rhp_replxx UTF8)
