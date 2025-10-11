#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <cryptopp/integer.h>

namespace crypto::utils {

std::vector<std::uint8_t> string_to_bytes(const std::string &input);
std::string bytes_to_string(const std::vector<std::uint8_t> &bytes);

std::string bytes_to_hex(const std::vector<std::uint8_t> &bytes, bool uppercase = false);
std::vector<std::uint8_t> hex_to_bytes(std::string_view hex);

std::vector<std::uint8_t> bigint_to_bytes(const CryptoPP::Integer &value,
                                          std::size_t min_size = 0);
CryptoPP::Integer bytes_to_bigint(const std::vector<std::uint8_t> &bytes);

std::string bigint_to_hex(const CryptoPP::Integer &value, std::size_t min_size = 0);
CryptoPP::Integer hex_to_bigint(std::string_view hex);

} // namespace crypto::utils

#endif // CRYPTO_UTILS_H
