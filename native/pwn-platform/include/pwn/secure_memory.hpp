// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file
 * @brief Helpers for handling secret data in memory.
 */

#pragma once

#include <cstdint>
#include <span>

namespace pwn {

	/**
	 * @brief Overwrites memory with zeros in a way the compiler can't remove.
	 *
	 * A plain `std::memset` before freeing memory is a "dead store" that the
	 * optimizer is allowed to delete. This function uses the operating system's
	 * guaranteed wipe instead.
	 *
	 * @param data The bytes to overwrite. May be empty.
	 */
	void secure_zero(std::span<std::uint8_t> data) noexcept;

}  // namespace pwn