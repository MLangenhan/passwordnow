# SPDX-License-Identifier: AGPL-3.0-or-later

add_library(pwn_platform
    src/secure_memory.cpp)
add_library(pwn::platform ALIAS pwn_platform)

target_include_directories(pwn_platform PUBLIC include)
pwn_set_warnings(pwn_platform)

if(PWN_BUILD_TESTS)
    add_executable(pwn_platform_tests
        tests/secure_memory_test.cpp)
    target_link_libraries(pwn_platform_tests PRIVATE
        pwn::platform
        GTest::gtest_main)
    pwn_set_warnings(pwn_platform_tests)
    gtest_discover_tests(pwn_platform_tests)
endif()