// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * @file
 * @brief A byte buffer for secrets that wipes itself when destroyed.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <memory>
#include <span>

namespace pwn {

    /**
     * @brief A fixed-size byte buffer for secret data such as passwords and keys.
     *
     * Guarantees:
     * - The contents are overwritten with zeros when the buffer is destroyed.
     * - Printing it never shows the contents.
     * - It can't be copied, only moved, so no unnoticed duplicates exist.
     */
    class SecretBuffer {
    public:
        /**
         * @brief Creates a buffer of `size` zero bytes, ready to be filled with a secret.
         *
         * @param size Number of bytes in the buffer, e.g. `32` for a 256-bit key.
         * @return A new buffer containing `size` zero bytes.
         */
        [[nodiscard]] static SecretBuffer zeroed(std::size_t size);

        /**
         * @brief Copies `source` into a new buffer and then wipes `source`.
         *
         * This way no unprotected copy of the secret is left behind.
         *
         * @param source The plaintext bytes. They are overwritten with zeros.
         * @return A new buffer holding a copy of the original `source` bytes.
         */
        [[nodiscard]] static SecretBuffer take_from(std::span<std::uint8_t> source);

        /** @brief Wipes the contents before the memory is freed. */
        ~SecretBuffer();

        SecretBuffer(const SecretBuffer&) = delete;
        SecretBuffer& operator=(const SecretBuffer&) = delete;

        /**
         * @brief Takes over the contents of `other`. `other` is left empty.
         *
         * @param other The buffer to move from.
         */
        SecretBuffer(SecretBuffer&& other) noexcept;

        /**
         * @brief Wipes the own contents, then takes over those of `other`.
         *
         * @param other The buffer to move from. It is left empty.
         * @return This buffer.
         */
        SecretBuffer& operator=(SecretBuffer&& other) noexcept;

        /**
         * @brief Gives read access to the secret bytes without copying them.
         *
         * @return A read-only view. It becomes invalid when this buffer is
         *         destroyed or moved from. Unlike Rust, C++ doesn't check this.
         */
        [[nodiscard]] std::span<const std::uint8_t> expose_secret() const noexcept;

        /**
         * @brief Gives write access to the secret bytes, e.g. to fill in a key.
         *
         * @return A writable view. Same lifetime rules as expose_secret().
         */
        [[nodiscard]] std::span<std::uint8_t> expose_secret_mut() noexcept;

        /** @brief Returns the number of bytes. The size itself is not secret. */
        [[nodiscard]] std::size_t size() const noexcept;

        /** @brief Returns `true` if the buffer holds no bytes. */
        [[nodiscard]] bool empty() const noexcept;

    private:
        explicit SecretBuffer(std::size_t size);

        void wipe() noexcept;

        // `unique_ptr<uint8_t[]>` instead of `std::vector`: a vector can grow, and
        // growing moves the data to a new allocation and frees the old one
        // *without* wiping it. This buffer has a fixed size and never moves.
        std::unique_ptr<std::uint8_t[]> data_;
        std::size_t size_ = 0;
    };

    /**
     * @brief Prints only the size, never the contents.
     *
     * Example output: `SecretBuffer([REDACTED; 7 bytes])`.
     *
     * @param out The stream to write to.
     * @param secret The buffer to describe.
     * @return `out`, so that `<<` calls can be chained.
     */
    std::ostream& operator<<(std::ostream& out, const SecretBuffer& secret);

}  // namespace pwn