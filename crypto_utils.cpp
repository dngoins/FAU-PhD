#include "crypto_utils.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace crypto::utils {

std::vector<std::uint8_t> string_to_bytes(const std::string &input) {
    return std::vector<std::uint8_t>(input.begin(), input.end());
}

std::string bytes_to_string(const std::vector<std::uint8_t> &bytes) {
    return std::string(bytes.begin(), bytes.end());
}

std::string bytes_to_hex(const std::vector<std::uint8_t> &bytes, bool uppercase) {
    std::ostringstream oss;
    if (uppercase) {
        oss.setf(std::ios::uppercase);
    }
    oss << std::hex << std::setfill('0');
    for (auto byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<std::uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    auto is_hex_digit = [](unsigned char c) {
        return std::isxdigit(c) != 0;
    };

    std::vector<char> filtered;
    filtered.reserve(hex.size());
    for (char c : hex) {
        if (std::isspace(static_cast<unsigned char>(c)) != 0) {
            continue;
        }
        if (c == 'x' || c == 'X') {
            if (!filtered.empty() && filtered.back() == '0') {
                filtered.pop_back();
                continue;
            }
        }
        if (!is_hex_digit(static_cast<unsigned char>(c))) {
            throw std::invalid_argument("Input contains non-hexadecimal characters");
        }
        filtered.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }

    if (filtered.size() % 2 != 0) {
        filtered.insert(filtered.begin(), '0');
    }

    for (std::size_t i = 0; i < filtered.size(); i += 2) {
        unsigned int value = 0;
        std::stringstream ss;
        ss << std::hex << filtered[i] << filtered[i + 1];
        ss >> value;
        bytes.push_back(static_cast<std::uint8_t>(value));
    }

    return bytes;
}

std::vector<std::uint8_t> bigint_to_bytes(const CryptoPP::Integer &value, std::size_t min_size) {
    std::size_t byte_count = value.MinEncodedSize();
    if (byte_count == 0U) {
        byte_count = 1U;
    }
    byte_count = std::max(byte_count, min_size);

    std::vector<std::uint8_t> buffer(byte_count, 0U);
    if (!value.IsZero()) {
        value.Encode(buffer.data(), buffer.size());
    }
    return buffer;
}

CryptoPP::Integer bytes_to_bigint(const std::vector<std::uint8_t> &bytes) {
    if (bytes.empty()) {
        return CryptoPP::Integer::Zero();
    }
    return CryptoPP::Integer(bytes.data(), static_cast<std::size_t>(bytes.size()));
}

std::string bigint_to_hex(const CryptoPP::Integer &value, std::size_t min_size) {
    auto bytes = bigint_to_bytes(value, min_size);
    return bytes_to_hex(bytes);
}

CryptoPP::Integer hex_to_bigint(std::string_view hex) {
    auto bytes = hex_to_bytes(hex);
    return bytes_to_bigint(bytes);
}

} // namespace crypto::utils
