# cmake -DROOT=<Src> -DGENERATED=<generated include dir> -P check_ascii.cmake
# Fails when a public header (or the generated build_config.hpp) has a byte outside ASCII.
file(GLOB_RECURSE headers LIST_DIRECTORIES false "${ROOT}/*.hpp" "${ROOT}/*.h" "${GENERATED}/*.hpp")
set(bad "")
foreach(header IN LISTS headers)
    file(READ "${header}" bytes HEX)
    # Hex pairs 80..ff are the non-ASCII bytes: a pair whose first digit is 8..f, counted in whole
    # pairs from the start of the string.
    string(REGEX MATCH "^(..)*[89a-f]" hit "${bytes}")
    if(hit)
        list(APPEND bad "${header}")
    endif()
endforeach()
list(LENGTH headers count)
if(bad)
    list(JOIN bad "\n  " bad_list)
    message(FATAL_ERROR "non-ASCII bytes in public headers:\n  ${bad_list}")
endif()
message(STATUS "${count} headers are ASCII")
