/*
Author: Dwight Goins
Course: 6730 Computer Data Security (Cryptography)
Date: 10.11.2025

Summary:
    Implementation a hybrid cryptosystem that combines ElGamal public-key encryption with AES symmetric-key encryption. The hybrid system will use ElGamal to securely exchange a randomly generated AES session key, which will then be used to encrypt and decrypt the actual message data using AES in CBC mode with PKCS#7 padding.
    
    The program will request the user to input or generate an ElGamal key pair (public and private keys). It will also allow the user to generate or input an AES session key. The user can then encrypt a plaintext message, which will involve encrypting the AES session key with the ElGamal public key and then encrypting the message with AES using that session key. For decryption, the program will use the ElGamal private key to recover the AES session key and then decrypt the message with AES.
    
*/
#ifndef HYBRID_CRYPTO_H
#define HYBRID_CRYPTO_H
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <cryptopp/osrng.h>

#include "AES.h"
#include "crypto_utils.h"
#include "el_gamal_pke.h"

namespace hybrid {

struct HybridCiphertext {
    std::vector<elgamal::CipherChunk> wrapped_session_key;
    std::vector<std::uint8_t> iv;
    std::vector<std::uint8_t> ciphertext;
};

class HybridCryptoService {
public:
    void generate_key_pair(std::size_t bit_length, CryptoPP::RandomNumberGenerator &rng);

    void set_public_key(const elgamal::PublicKey &key);
    void set_private_key(const elgamal::PrivateKey &key);
    [[nodiscard]] bool has_public_key() const noexcept;
    [[nodiscard]] bool has_private_key() const noexcept;

    [[nodiscard]] const elgamal::PublicKey &public_key() const;
    [[nodiscard]] const elgamal::PrivateKey &private_key() const;

    void set_public_key_from_hex(std::string_view p_hex,
                                 std::string_view g_hex,
                                 std::string_view y_hex);
    void set_private_key_from_hex(std::string_view p_hex,
                                  std::string_view g_hex,
                                  std::string_view x_hex);
    [[nodiscard]] std::tuple<std::string, std::string, std::string> public_key_hex() const;
    [[nodiscard]] std::tuple<std::string, std::string, std::string> private_key_hex() const;

    void generate_session_key(CryptoPP::RandomNumberGenerator &rng);
    void set_session_key(const AES128::Key &key);
    void set_session_key_from_hex(std::string_view hex);
    [[nodiscard]] bool has_session_key() const noexcept;
    [[nodiscard]] const AES128::Key &session_key() const;
    [[nodiscard]] std::string session_key_hex() const;

    HybridCiphertext encrypt(const std::vector<std::uint8_t> &plaintext,
                             CryptoPP::RandomNumberGenerator &rng) const;
    std::vector<std::uint8_t> decrypt(const HybridCiphertext &ciphertext,
                                      bool update_session_key = true);

private:
    static constexpr std::size_t kBlockSize = AES128::Key{}.size();

    static std::vector<std::uint8_t> pkcs7_pad(const std::vector<std::uint8_t> &input);
    static std::vector<std::uint8_t> pkcs7_unpad(const std::vector<std::uint8_t> &input);
    static AES128::Block vector_to_block(const std::vector<std::uint8_t> &buffer, std::size_t offset);
    static void block_to_vector(const AES128::Block &block, std::vector<std::uint8_t> &out);
    static void xor_block(AES128::Block &lhs, const AES128::Block &rhs);

    elgamal::PublicKey public_key_{};
    elgamal::PrivateKey private_key_{};
    AES128::Key session_key_{};

    bool has_public_key_ = false;
    bool has_private_key_ = false;
    bool has_session_key_ = false;
};

} // namespace hybrid

#endif // HYBRID_CRYPTO_H
