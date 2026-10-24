include_guard(GLOBAL)

# Installs RHP's license and notices, and the licenses of the third-party code compiled into the
# installed archives (share/doc/rhp/licenses), so a binary built from an installed RHP can carry them.
# THIRD_PARTY_LICENSES.md lists what is included and under which terms.
install(FILES
    "${PROJECT_SOURCE_DIR}/LICENSE"
    "${PROJECT_SOURCE_DIR}/NOTICE"
    "${PROJECT_SOURCE_DIR}/THIRD_PARTY_LICENSES.md"
    DESTINATION "${CMAKE_INSTALL_DOCDIR}"
    COMPONENT development
)

set(rhp_license_dir "${CMAKE_INSTALL_DOCDIR}/licenses")

if(RHP_ENABLE)
    # Lua keeps its license at the end of lua.h.
    file(STRINGS "${lua_SOURCE_DIR}/lua.h" rhp_lua_lines)
    set(rhp_lua_license "")
    set(rhp_in_license FALSE)
    foreach(line IN LISTS rhp_lua_lines)
        if(line MATCHES "^\\* Copyright \\(C\\) [0-9-]+ Lua\\.org")
            set(rhp_in_license TRUE)
        endif()
        if(rhp_in_license)
            string(REGEX REPLACE "^\\* ?" "" line "${line}")
            string(APPEND rhp_lua_license "${line}\n")
            if(line MATCHES "SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE")
                break()
            endif()
        endif()
    endforeach()
    if(rhp_lua_license STREQUAL "")
        message(FATAL_ERROR "RHP: can't find the license in ${lua_SOURCE_DIR}/lua.h")
    endif()
    file(WRITE "${PROJECT_BINARY_DIR}/package/licenses/lua.txt" "${rhp_lua_license}")

    install(FILES "${PROJECT_BINARY_DIR}/package/licenses/lua.txt" DESTINATION "${rhp_license_dir}" COMPONENT development)
    install(FILES "${monocypher_SOURCE_DIR}/LICENCE.md" DESTINATION "${rhp_license_dir}" RENAME monocypher.md COMPONENT development)
    install(FILES "${asio_SOURCE_DIR}/LICENSE_1_0.txt" DESTINATION "${rhp_license_dir}" RENAME asio.txt COMPONENT development)
    if(RHP_TLS_HAS_MBEDTLS)
        install(FILES "${mbedtls_SOURCE_DIR}/LICENSE" DESTINATION "${rhp_license_dir}" RENAME mbedtls.txt COMPONENT development)
        install(FILES "${mbedtls_SOURCE_DIR}/tf-psa-crypto/LICENSE" DESTINATION "${rhp_license_dir}" RENAME tf-psa-crypto.txt COMPONENT development)
    endif()
endif()

if(RHP_BUILD_TOOLS AND RHP_ENABLE)
    install(FILES "${CLI11_SOURCE_DIR}/LICENSE" DESTINATION "${rhp_license_dir}" RENAME cli11.txt COMPONENT tools)
    install(FILES "${replxx_SOURCE_DIR}/LICENSE.md" DESTINATION "${rhp_license_dir}" RENAME replxx.md COMPONENT tools)
endif()
