# SPDX - License - Identifier: AGPL - 3.0 - or -later

cmake_minimum_required(VERSION 3.25)

project(PasswordNow
    VERSION 0.1.0
    DESCRIPTION "Open-source zero-knowledge password manager"
    LANGUAGES CXX)

    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    set(CMAKE_CXX_EXTENSIONS OFF)

    option(PWN_BUILD_TESTS "Build the C++ unit tests" ON)

    # Strict compiler warnings for our own targets.Every warning is an error.
    function(pwn_set_warnings target)
    if (MSVC)
        target_compile_options(${ target } PRIVATE / W4 / WX / permissive - )
    else()
        target_compile_options(${ target } PRIVATE
            - Wall - Wextra - Wpedantic - Wconversion - Wshadow - Werror)
        endif()
        endfunction()

        if (PWN_BUILD_TESTS)
            enable_testing()

            include(FetchContent)
            FetchContent_Declare(googletest
                URL https ://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
URL_HASH SHA256 = 65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
DOWNLOAD_EXTRACT_TIMESTAMP TRUE
SYSTEM)
# Windows: link GoogleTest against the same C runtime as our code.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)
endif()

add_subdirectory(native / pwn - platform)