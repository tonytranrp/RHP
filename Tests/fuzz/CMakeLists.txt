# Fuzz targets (frame · envelope · msgpack · sandbox_escape · network). Each builds as a replay driver that
# ctest runs (seeds + deterministic mutations) and, with RHP_FUZZ=ON (Clang), also as a libFuzzer
# executable `rhp_fuzz_<name>` for long runs: see README.md.
function(rhp_add_fuzz name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "SOURCE" "LINKS")
    add_executable(rhp_fuzz_${name}_replay ${arg_SOURCE} replay_main.cpp)
    target_link_libraries(rhp_fuzz_${name}_replay PRIVATE ${arg_LINKS})
    rhp_set_warnings(rhp_fuzz_${name}_replay)
    set_target_properties(rhp_fuzz_${name}_replay PROPERTIES FOLDER "tests/fuzz")
    add_test(NAME fuzz.${name} COMMAND rhp_fuzz_${name}_replay --iterations 3000)
    set_tests_properties(fuzz.${name} PROPERTIES LABELS fuzz TIMEOUT 600)

    if(RHP_FUZZ)
        add_executable(rhp_fuzz_${name} ${arg_SOURCE})
        target_link_libraries(rhp_fuzz_${name} PRIVATE ${arg_LINKS})
        target_compile_options(rhp_fuzz_${name} PRIVATE -fsanitize=fuzzer)
        target_link_options(rhp_fuzz_${name} PRIVATE -fsanitize=fuzzer)
        set_target_properties(rhp_fuzz_${name} PROPERTIES FOLDER "tests/fuzz")
    endif()
endfunction()

rhp_add_fuzz(frame SOURCE frame_fuzz.cpp LINKS Rhp::wire)
rhp_add_fuzz(msgpack SOURCE msgpack_fuzz.cpp LINKS Rhp::wire)
rhp_add_fuzz(envelope SOURCE envelope_fuzz.cpp LINKS Rhp::wire)
rhp_add_fuzz(sandbox_escape SOURCE sandbox_fuzz.cpp LINKS Rhp::script)
rhp_add_fuzz(network SOURCE network_fuzz.cpp LINKS Rhp::net)
