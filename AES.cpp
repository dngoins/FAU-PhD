/*
Author: Dwight Goins
Course: 6730 Computer Data Security (Cryptography)
Date: 09.27.2025
Synopsis:
    Rudimentary implementation of the AES Encryption/Decryption algorithm
    
*/

#include "AES.h"
#include "Euclidean.h"
#include <iostream>
#include <vector>
#include <stdexcept>
#include <array>
#include <iomanip> // for std::setw and std::setfill
#include <sstream> // for std::stringstream
#include <bitset> // for std::bitset
#include <cstring> // for std::memcpy
#include <algorithm> // for std::copy
#include <cstdint> // for uint8_t
#include <string> // for std::string and std::getline
#include <utility>

using namespace std;

// This implementation will take in 128 bit blocks (16 bytes) and a 128 bit key (16 bytes).
// The key will be expanded to 11 round keys (each 16 bytes) for the 10 rounds of AES-128.
// The state will be represented as a 4x4 matrix of bytes (uint8_t).
// The input plaintext and output ciphertext will be represented as 16-byte arrays.
// The implementation will include the following functions:
// - KeyExpansion: Expands the 128-bit key into 11 round keys.
// - AddRoundKey: XORs the state with the round key.
// - SubBytes: Applies the S-box to each byte of the state.
// - ShiftRows: Shifts the rows of the state.
// - MixColumns: Mixes the columns of the state.
// - EncryptBlock: Encrypts a single 16-byte block of plaintext.
// - DecryptBlock: Decrypts a single 16-byte block of ciphertext.
// - Helper functions for converting between byte arrays and the state matrix.
// - Main function to demonstrate encryption and decryption.
// - This will also include padding functions for mode of operation using CBC.
// Note: This implementation is for educational purposes and may not be optimized for performance or security.


// Fist is the Byte Substitution
// Create the SubBytes function
// take in the input from the user, convert it to the matrix
// then use the affine transformation: 7x^61 + 99  mod 2305843009213693951

namespace {
    constexpr uint64_t AES_PRIME = 2305843009213693951ULL; // 2^61 - 1, safe in 64 bits

    using State = array<array<uint8_t, 4>, 4>;

    uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t modulus) {
        uint64_t result = 0;
        a %= modulus;
        while (b > 0) {
            if (b & 1ULL) {
                result = (result + a) % modulus;
            }
            a = (a << 1U) % modulus;
            b >>= 1U;
        }
        return result;
    }

    uint64_t mod_pow(uint64_t base, uint64_t exponent, uint64_t modulus) {
        if (modulus == 1) {
            return 0;
        }
        uint64_t result = 1;
        base %= modulus;
        while (exponent > 0) {
            if (exponent & 1ULL) {
                result = mul_mod(result, base, modulus);
            }
            exponent >>= 1U;
            if (exponent > 0) {
                base = mul_mod(base, base, modulus);
            }
        }
        return result;
    }

    array<uint8_t, 256> SBOX{};
    array<uint8_t, 256> INV_SBOX{};
    bool SBOX_READY = false;

    void initialise_sboxes() {
        array<pair<uint64_t, uint16_t>, 256> scored{};
        for (uint16_t value = 0; value < scored.size(); ++value) {
            const uint64_t power = mod_pow(static_cast<uint64_t>(value), 61ULL, AES_PRIME);
            const uint64_t transformed = (7ULL * power + 99ULL) % AES_PRIME;
            scored[value] = {transformed, value};
        }

        sort(scored.begin(), scored.end(), [](const auto& lhs, const auto& rhs) {
            if (lhs.first == rhs.first) {
                return lhs.second < rhs.second;
            }
            return lhs.first < rhs.first;
        });

        for (size_t rank = 0; rank < scored.size(); ++rank) {
            const uint8_t original = static_cast<uint8_t>(scored[rank].second);
            const uint8_t substituted = static_cast<uint8_t>(rank);
            SBOX[original] = substituted;
            INV_SBOX[substituted] = original;
        }
        SBOX_READY = true;
    }

    void ensure_sboxes() {
        if (!SBOX_READY) {
            initialise_sboxes();
        }
    }

    inline uint8_t sbox_lookup(uint8_t value) {
        ensure_sboxes();
        return SBOX[static_cast<size_t>(value)];
    }

    inline uint8_t inv_sbox_lookup(uint8_t value) {
        ensure_sboxes();
        return INV_SBOX[static_cast<size_t>(value)];
    }

    // Helper function: convert 16-byte block into AES state matrix
    State bytes_to_state(const AES128::Block& block) {
        State state{};
        for (size_t col = 0; col < 4; ++col) {
            for (size_t row = 0; row < 4; ++row) {
                state[row][col] = block[row + 4 * col];
            }
        }
        return state;
    }

    // Helper function: convert AES state matrix back into 16-byte block
    AES128::Block state_to_bytes(const State& state) {
        AES128::Block block{};
        for (size_t col = 0; col < 4; ++col) {
            for (size_t row = 0; row < 4; ++row) {
                block[row + 4 * col] = state[row][col];
            }
        }
        return block;
    }

    // SubBytes step: apply custom S-box to every state byte
    void sub_bytes(State& state) {
        ensure_sboxes();
        for (auto& row : state) {
            for (auto& value : row) {
                value = sbox_lookup(value);
            }
        }
    }

    // Inverse SubBytes step: invert the custom S-box for decryption
    void inv_sub_bytes(State& state) {
        ensure_sboxes();
        for (auto& row : state) {
            for (auto& value : row) {
                value = inv_sbox_lookup(value);
            }
        }
    }

    // ShiftRows step: rotate state rows for byte transposition
    void shift_rows(State& state) {
        rotate(state[1].begin(), state[1].begin() + 1, state[1].end());
        rotate(state[2].begin(), state[2].begin() + 2, state[2].end());
        rotate(state[3].begin(), state[3].begin() + 3, state[3].end());
    }

    // Inverse ShiftRows step: undo row rotations during decryption
    void inv_shift_rows(State& state) {
        rotate(state[1].rbegin(), state[1].rbegin() + 1, state[1].rend());
        rotate(state[2].rbegin(), state[2].rbegin() + 2, state[2].rend());
        rotate(state[3].rbegin(), state[3].rbegin() + 3, state[3].rend());
    }

    uint8_t gmul(uint8_t a, uint8_t b) {
        uint8_t product = 0;
        for (int i = 0; i < 8; ++i) {
            if (b & 1U) {
                product ^= a;
            }
            const bool hi_bit = (a & 0x80U) != 0;
            a <<= 1U;
            if (hi_bit) {
                a ^= 0x1BU;
            }
            b >>= 1U;
        }
        return product;
    }

    // MixColumns step: mix bytes within each column over GF(2^8)
    void mix_columns(State& state) {
        for (size_t col = 0; col < 4; ++col) {
            const uint8_t s0 = state[0][col];
            const uint8_t s1 = state[1][col];
            const uint8_t s2 = state[2][col];
            const uint8_t s3 = state[3][col];
            state[0][col] = gmul(0x02U, s0) ^ gmul(0x03U, s1) ^ s2 ^ s3;
            state[1][col] = s0 ^ gmul(0x02U, s1) ^ gmul(0x03U, s2) ^ s3;
            state[2][col] = s0 ^ s1 ^ gmul(0x02U, s2) ^ gmul(0x03U, s3);
            state[3][col] = gmul(0x03U, s0) ^ s1 ^ s2 ^ gmul(0x02U, s3);
        }
    }

    // Inverse MixColumns step: reverse column mixing for decryption
    void inv_mix_columns(State& state) {
        for (size_t col = 0; col < 4; ++col) {
            const uint8_t s0 = state[0][col];
            const uint8_t s1 = state[1][col];
            const uint8_t s2 = state[2][col];
            const uint8_t s3 = state[3][col];
            state[0][col] = gmul(0x0EU, s0) ^ gmul(0x0BU, s1) ^ gmul(0x0DU, s2) ^ gmul(0x09U, s3);
            state[1][col] = gmul(0x09U, s0) ^ gmul(0x0EU, s1) ^ gmul(0x0BU, s2) ^ gmul(0x0DU, s3);
            state[2][col] = gmul(0x0DU, s0) ^ gmul(0x09U, s1) ^ gmul(0x0EU, s2) ^ gmul(0x0BU, s3);
            state[3][col] = gmul(0x0BU, s0) ^ gmul(0x0DU, s1) ^ gmul(0x09U, s2) ^ gmul(0x0EU, s3);
        }
    }

    // AddRoundKey step: XOR round key into current state
    void add_round_key(State& state, const array<uint8_t, 16>& round_key) {
        for (size_t col = 0; col < 4; ++col) {
            for (size_t row = 0; row < 4; ++row) {
                state[row][col] ^= round_key[row + 4 * col];
            }
        }
    }

    // KeyExpansion: derive 11 round keys from the initial 128-bit key
    array<array<uint8_t, 16>, 11> expand_key(const AES128::Key& key) {
        ensure_sboxes();
        constexpr array<uint8_t, 10> RCON = {0x01U, 0x02U, 0x04U, 0x08U, 0x10U, 0x20U, 0x40U, 0x80U, 0x1BU, 0x36U};
        array<array<uint8_t, 4>, 44> words{};

        for (size_t i = 0; i < 4; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                words[i][j] = key[4 * i + j];
            }
        }

        for (size_t i = 4; i < words.size(); ++i) {
            array<uint8_t, 4> temp = words[i - 1];
            if (i % 4U == 0U) {
                rotate(temp.begin(), temp.begin() + 1, temp.end());
                for (auto& byte : temp) {
                    byte = sbox_lookup(byte);
                }
                temp[0] ^= RCON[(i / 4U) - 1U];
            }
            for (size_t j = 0; j < temp.size(); ++j) {
                words[i][j] = words[i - 4][j] ^ temp[j];
            }
        }

        array<array<uint8_t, 16>, 11> round_keys{};
        for (size_t round = 0; round < round_keys.size(); ++round) {
            for (size_t word_index = 0; word_index < 4; ++word_index) {
                for (size_t byte_index = 0; byte_index < 4; ++byte_index) {
                    round_keys[round][word_index * 4 + byte_index] =
                        words[round * 4 + word_index][byte_index];
                }
            }
        }
        return round_keys;
    }
}

AES128::AES128(const Key& key) : round_keys_(expand_key(key)) {}

// EncryptBlock: process a single 16-byte block through 10 AES rounds
AES128::Block AES128::encrypt_block(const Block& plaintext) const {
        State state = bytes_to_state(plaintext);
        add_round_key(state, round_keys_[0]);
        for (size_t round = 1; round < 10; ++round) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round_keys_[round]);
        }
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, round_keys_[10]);
        return state_to_bytes(state);
}

// DecryptBlock: reverse AES rounds to recover the original 16-byte block
AES128::Block AES128::decrypt_block(const Block& ciphertext) const {
        State state = bytes_to_state(ciphertext);
        add_round_key(state, round_keys_[10]);
        for (size_t round = 9; round > 0; --round) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, round_keys_[round]);
            inv_mix_columns(state);
        }
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys_[0]);
        return state_to_bytes(state);
}

namespace {
    // Helper: shape user input into a 128-bit key buffer
    AES128::Key string_to_key(const string& input) {
        AES128::Key key{};
        const size_t copy_len = min(input.size(), key.size());
        copy_n(reinterpret_cast<const uint8_t*>(input.data()), copy_len, key.begin());
        return key;
    }

    // Helper: shape user input into a 16-byte plaintext block
    AES128::Block string_to_block(const string& input) {
        AES128::Block block{};
        const size_t copy_len = min(input.size(), block.size());
        copy_n(reinterpret_cast<const uint8_t*>(input.data()), copy_len, block.begin());
        return block;
    }
}

int main() {
    // Demonstration driver: collect input, encrypt, and decrypt a single block
    cout << "Enter up to 16 characters for the AES key: ";
    string key_input;
    getline(cin, key_input);

    cout << "Enter up to 16 characters of plaintext: ";
    string plaintext;
    getline(cin, plaintext);

    const AES128::Key key = string_to_key(key_input);
    const AES128 cipher(key);

    const AES128::Block plain_block = string_to_block(plaintext);
    const AES128::Block cipher_block = cipher.encrypt_block(plain_block);
    const AES128::Block decrypted_block = cipher.decrypt_block(cipher_block);

    cout << "Ciphertext (hex): ";
    for (const auto byte : cipher_block) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << ' ';
    }
    cout << dec << '\n';

    const size_t original_len = min<size_t>(plaintext.size(), AES128::Block{}.size());
    string recovered(decrypted_block.begin(), decrypted_block.begin() + original_len);
    cout << "Recovered plaintext: " << recovered << '\n';

    // Note: Padding/CBC modes not yet implemented—single-block demo only.
    return 0;
}


