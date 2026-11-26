// SPDX-License-Identifier: AGPL-3.0-or-later

#include "pwn/secure_memory.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>

namespace {

    TEST(SecureZero, OverwritesAllBytesWithZero) {
        std::array<std::uint8_t, 7> data{ 'h', 'u', 'n', 't', 'e', 'r', '2' };

        pwn::secure_zero(data);

        EXPECT_TRUE(std::ranges::all_of(data, [](std::uint8_t b) { return b == 0; }));
    }

    TEST(SecureZero, OnlyTouchesTheGivenRange) {
        std::array<std::uint8_t, 4> data{ 1, 2, 3, 4 };

        pwn::secure_zero(std::span(data).first(2));

        EXPECT_EQ(data, (std::array<std::uint8_t, 4>{0, 0, 3, 4}));
    }

    TEST(SecureZero, AcceptsEmptyRange) {
        pwn::secure_zero({});
    }

}  // namespace