
// if not define, define
#ifndef AES_H
#define AES_H
#pragma once


#include <array>
#include <cstdint>

class AES128 final {
public:
	using Block = std::array<uint8_t, 16>;
	using Key = std::array<uint8_t, 16>;

	explicit AES128(const Key& key);

	Block encrypt_block(const Block& plaintext) const;
	Block decrypt_block(const Block& ciphertext) const;

private:
	std::array<std::array<uint8_t, 16>, 11> round_keys_{};
};

#endif // AES_H