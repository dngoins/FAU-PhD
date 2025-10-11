#include "hybrid_crypto.h"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <vector>

namespace hybrid {

void HybridCryptoService::generate_key_pair(std::size_t bit_length,
                                            CryptoPP::RandomNumberGenerator &rng) {
    auto [pub, priv] = elgamal::generate_keys(bit_length, rng);
    set_public_key(pub);
    set_private_key(priv);
}

void HybridCryptoService::set_public_key(const elgamal::PublicKey &key) {
    public_key_ = key;
    has_public_key_ = true;
}

void HybridCryptoService::set_private_key(const elgamal::PrivateKey &key) {
    private_key_ = key;
    has_private_key_ = true;
}

bool HybridCryptoService::has_public_key() const noexcept {
    return has_public_key_;
}

bool HybridCryptoService::has_private_key() const noexcept {
    return has_private_key_;
}

const elgamal::PublicKey &HybridCryptoService::public_key() const {
    if (!has_public_key_) {
        throw std::logic_error("Public key is not set");
    }
    return public_key_;
}

const elgamal::PrivateKey &HybridCryptoService::private_key() const {
    if (!has_private_key_) {
        throw std::logic_error("Private key is not set");
    }
    return private_key_;
}

void HybridCryptoService::set_public_key_from_hex(std::string_view p_hex,
                                                  std::string_view g_hex,
                                                  std::string_view y_hex) {
    elgamal::PublicKey key{
        crypto::utils::hex_to_bigint(p_hex),
        crypto::utils::hex_to_bigint(g_hex),
        crypto::utils::hex_to_bigint(y_hex)
    };
    set_public_key(key);
}

void HybridCryptoService::set_private_key_from_hex(std::string_view p_hex,
                                                   std::string_view g_hex,
                                                   std::string_view x_hex) {
    elgamal::PrivateKey key{
        crypto::utils::hex_to_bigint(p_hex),
        crypto::utils::hex_to_bigint(g_hex),
        crypto::utils::hex_to_bigint(x_hex)
    };
    set_private_key(key);
}

std::tuple<std::string, std::string, std::string> HybridCryptoService::public_key_hex() const {
    if (!has_public_key_) {
        throw std::logic_error("Public key is not set");
    }
    return {
        crypto::utils::bigint_to_hex(public_key_.p),
        crypto::utils::bigint_to_hex(public_key_.g),
        crypto::utils::bigint_to_hex(public_key_.y)
    };
}

std::tuple<std::string, std::string, std::string> HybridCryptoService::private_key_hex() const {
    if (!has_private_key_) {
        throw std::logic_error("Private key is not set");
    }
    return {
        crypto::utils::bigint_to_hex(private_key_.p),
        crypto::utils::bigint_to_hex(private_key_.g),
        crypto::utils::bigint_to_hex(private_key_.x)
    };
}

void HybridCryptoService::generate_session_key(CryptoPP::RandomNumberGenerator &rng) {
    rng.GenerateBlock(session_key_.data(), session_key_.size());
    has_session_key_ = true;
}

void HybridCryptoService::set_session_key(const AES128::Key &key) {
    session_key_ = key;
    has_session_key_ = true;
}

void HybridCryptoService::set_session_key_from_hex(std::string_view hex) {
    auto bytes = crypto::utils::hex_to_bytes(hex);
    if (bytes.size() != session_key_.size()) {
        throw std::invalid_argument("Session key must be exactly 128 bits");
    }
    std::copy(bytes.begin(), bytes.end(), session_key_.begin());
    has_session_key_ = true;
}

bool HybridCryptoService::has_session_key() const noexcept {
    return has_session_key_;
}

const AES128::Key &HybridCryptoService::session_key() const {
    if (!has_session_key_) {
        throw std::logic_error("Session key is not set");
    }
    return session_key_;
}

std::string HybridCryptoService::session_key_hex() const {
    if (!has_session_key_) {
        throw std::logic_error("Session key is not set");
    }
    return crypto::utils::bytes_to_hex(std::vector<std::uint8_t>(session_key_.begin(), session_key_.end()));
}

HybridCiphertext HybridCryptoService::encrypt(const std::vector<std::uint8_t> &plaintext,
                                              CryptoPP::RandomNumberGenerator &rng) const {
    if (!has_public_key_) {
        throw std::logic_error("Public key is required for encryption");
    }
    if (!has_session_key_) {
        throw std::logic_error("Session key is required for encryption");
    }
    HybridCiphertext result;

    std::vector<std::uint8_t> key_bytes(session_key_.begin(), session_key_.end());
    result.wrapped_session_key = elgamal::encrypt_bytes(public_key_, key_bytes, rng);

    result.iv.resize(kBlockSize);
    rng.GenerateBlock(result.iv.data(), result.iv.size());

    std::vector<std::uint8_t> padded = pkcs7_pad(plaintext);

    AES128 cipher(session_key_);

    AES128::Block previous = vector_to_block(result.iv, 0);
    result.ciphertext.reserve(padded.size());

    for (std::size_t offset = 0; offset < padded.size(); offset += kBlockSize) {
        AES128::Block block = vector_to_block(padded, offset);
        xor_block(block, previous);
        AES128::Block encrypted_block = cipher.encrypt_block(block);
        block_to_vector(encrypted_block, result.ciphertext);
        previous = encrypted_block;
    }

    return result;
}

std::vector<std::uint8_t> HybridCryptoService::decrypt(const HybridCiphertext &ciphertext,
                                                       bool update_session_key) {
    if (!has_private_key_) {
        throw std::logic_error("Private key is required for decryption");
    }

    AES128::Key active_key{};
    if (!ciphertext.wrapped_session_key.empty()) {
        auto key_bytes = elgamal::decrypt_bytes(private_key_, ciphertext.wrapped_session_key);
        if (key_bytes.size() != active_key.size()) {
            throw std::runtime_error("Wrapped session key has unexpected length");
        }
        std::copy(key_bytes.begin(), key_bytes.end(), active_key.begin());
        if (update_session_key) {
            session_key_ = active_key;
            has_session_key_ = true;
        }
    } else {
        if (!has_session_key_) {
            throw std::logic_error("Session key is not available");
        }
        active_key = session_key_;
    }

    if (ciphertext.iv.size() != kBlockSize) {
        throw std::runtime_error("Invalid IV length");
    }
    if (ciphertext.ciphertext.empty() || ciphertext.ciphertext.size() % kBlockSize != 0) {
        throw std::runtime_error("Ciphertext length is not a multiple of block size");
    }

    AES128 cipher(active_key);
    AES128::Block previous = vector_to_block(ciphertext.iv, 0);

    std::vector<std::uint8_t> recovered;
    recovered.reserve(ciphertext.ciphertext.size());

    for (std::size_t offset = 0; offset < ciphertext.ciphertext.size(); offset += kBlockSize) {
        AES128::Block block = vector_to_block(ciphertext.ciphertext, offset);
        AES128::Block decrypted_block = cipher.decrypt_block(block);
        xor_block(decrypted_block, previous);
        block_to_vector(decrypted_block, recovered);
        previous = block;
    }

    return pkcs7_unpad(recovered);
}

std::vector<std::uint8_t> HybridCryptoService::pkcs7_pad(const std::vector<std::uint8_t> &input) {
    std::vector<std::uint8_t> padded = input;
    std::uint8_t pad = static_cast<std::uint8_t>(kBlockSize - (padded.size() % kBlockSize));
    if (pad == 0U) {
        pad = static_cast<std::uint8_t>(kBlockSize);
    }
    padded.insert(padded.end(), pad, pad);
    return padded;
}

std::vector<std::uint8_t> HybridCryptoService::pkcs7_unpad(const std::vector<std::uint8_t> &input) {
    if (input.empty() || input.size() % kBlockSize != 0) {
        throw std::runtime_error("Invalid padded buffer");
    }
    std::uint8_t pad = input.back();
    if (pad == 0U || pad > kBlockSize) {
        throw std::runtime_error("Invalid PKCS#7 padding");
    }
    if (!std::all_of(input.end() - pad, input.end(), [pad](std::uint8_t value) { return value == pad; })) {
        throw std::runtime_error("Invalid PKCS#7 padding");
    }
    return std::vector<std::uint8_t>(input.begin(), input.end() - pad);
}

AES128::Block HybridCryptoService::vector_to_block(const std::vector<std::uint8_t> &buffer,
                                                   std::size_t offset) {
    if (offset + kBlockSize > buffer.size()) {
        throw std::out_of_range("Buffer slice exceeds block size");
    }
    AES128::Block block{};
    std::copy(buffer.begin() + static_cast<std::ptrdiff_t>(offset),
              buffer.begin() + static_cast<std::ptrdiff_t>(offset + kBlockSize),
              block.begin());
    return block;
}

void HybridCryptoService::block_to_vector(const AES128::Block &block, std::vector<std::uint8_t> &out) {
    out.insert(out.end(), block.begin(), block.end());
}

void HybridCryptoService::xor_block(AES128::Block &lhs, const AES128::Block &rhs) {
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        lhs[i] ^= rhs[i];
    }
}

} // namespace hybrid
