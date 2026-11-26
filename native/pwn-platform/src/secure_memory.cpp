// SPDX-License-Identifier: AGPL-3.0-or-later

// macOS: makes `memset_s` available. Must come before any standard header.
#if defined(__APPLE__)
#define __STDC_WANT_LIB_EXT1__ 1
#endif

#include "pwn/secure_memory.hpp"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#else
#include <string.h>
#endif

namespace pwn {

    void secure_zero(std::span<std::uint8_t> data) noexcept {
        if (data.empty()) {
            return;
        }
#if defined(_WIN32)
        SecureZeroMemory(data.data(), data.size());
#elif defined(__APPLE__)
        memset_s(data.data(), data.size(), 0, data.size());
#else
        explicit_bzero(data.data(), data.size());
#endif
    }

}  // namespace pwn