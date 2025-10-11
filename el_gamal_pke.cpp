#include "el_gamal_pke.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <cryptopp/modarith.h>
#include <cryptopp/nbtheory.h>

namespace elgamal {

namespace {

using CryptoPP::Integer;
using CryptoPP::PrimeAndGenerator;

const Integer kTwo = 2;
const Integer kOne = 1;
constexpr std::size_t kMinBitLength = 256;

BigInt mod_mul(const BigInt &a, const BigInt &b, const BigInt &modulus) {
    CryptoPP::ModularArithmetic mod(modulus);
    return mod.Multiply(a % modulus, b % modulus);
}

BigInt mod_exp(const BigInt &base, const BigInt &exponent, const BigInt &modulus) {
    return CryptoPP::a_exp_b_mod_c(base, exponent, modulus);
}

BigInt random_range(const BigInt &minimum,
                    const BigInt &maximum,
                    CryptoPP::RandomNumberGenerator &rng) {
    if (maximum < minimum) {
        throw std::invalid_argument("Invalid random range");
    }

    BigInt range = maximum - minimum + kOne;
    unsigned int bits = range.BitCount();
    BigInt candidate;
    do {
        candidate.Randomize(rng, bits);
    } while (candidate >= range);

    return minimum + candidate;
}

std::size_t determine_block_size(const BigInt &modulus) {
    BigInt threshold = kOne;
    const BigInt base = CryptoPP::Integer::Power2(8); // 256
    std::size_t block_bytes = 0;

    while (threshold * base < modulus) {
        threshold *= base;
        ++block_bytes;
    }

    if (block_bytes == 0) {
        block_bytes = 1;
    }

    return block_bytes;
}

std::vector<std::pair<BigInt, std::uint32_t>>
encode_bytes(const std::vector<std::uint8_t> &data, std::size_t block_bytes) {
    std::vector<std::pair<BigInt, std::uint32_t>> encoded;
    encoded.reserve((data.size() / block_bytes) + 1);

    if (data.empty()) {
        encoded.emplace_back(CryptoPP::Integer::Zero(), 0U);
        return encoded;
    }

    std::size_t index = 0;
    while (index < data.size()) {
        std::uint32_t len = 0;
        std::size_t chunk_len = std::min(block_bytes, data.size() - index);
        len = static_cast<std::uint32_t>(chunk_len);
        BigInt value(reinterpret_cast<const CryptoPP::byte *>(data.data() + index), len);
        encoded.emplace_back(value, len);
        index += chunk_len;
    }

    return encoded;
}

std::vector<std::uint8_t> decode_bytes(const std::vector<std::pair<BigInt, std::uint32_t>> &blocks) {
    std::size_t total_bytes = 0;
    for (const auto &entry : blocks) {
        total_bytes += entry.second;
    }

    std::vector<std::uint8_t> result;
    result.reserve(total_bytes);

    for (const auto &entry : blocks) {
        const BigInt &value = entry.first;
        std::uint32_t len = entry.second;
        if (len == 0U) {
            continue;
        }

        std::vector<std::uint8_t> chunk(len);
        value.Encode(reinterpret_cast<CryptoPP::byte *>(chunk.data()), len);
        result.insert(result.end(), chunk.begin(), chunk.end());
    }

    return result;
}

std::tuple<BigInt, BigInt, BigInt> generate_safe_prime_triplet(std::size_t bit_length,
                                                               CryptoPP::RandomNumberGenerator &rng) {
    if (bit_length < kMinBitLength) {
        throw std::invalid_argument("Bit length must be at least 256 bits");
    }

    PrimeAndGenerator generator;
    generator.Generate(1, rng, static_cast<int>(bit_length), static_cast<int>(bit_length - 1));
    return {generator.Prime(), generator.SubPrime(), generator.Generator()};
}

} // namespace

std::pair<PublicKey, PrivateKey> generate_keys(std::size_t bit_length,
                                               CryptoPP::RandomNumberGenerator &rng) {
    if (bit_length < kMinBitLength) {
        throw std::invalid_argument("ElGamal key size must be at least 256 bits");
    }

    auto [p, q, g] = generate_safe_prime_triplet(bit_length, rng);

    BigInt secret = random_range(kTwo, p - kTwo, rng);
    BigInt y = mod_exp(g, secret, p);

    PublicKey pub{p, g, y};
    PrivateKey priv{p, g, secret};
    return {pub, priv};
}

std::vector<CipherChunk> encrypt_bytes(const PublicKey &public_key,
                                       const std::vector<std::uint8_t> &data,
                                       CryptoPP::RandomNumberGenerator &rng) {
    std::size_t block_bytes = determine_block_size(public_key.p);
    auto encoded_blocks = encode_bytes(data, block_bytes);

    std::vector<CipherChunk> ciphertext;
    ciphertext.reserve(encoded_blocks.size());

    for (const auto &block : encoded_blocks) {
        const BigInt &message = block.first;
        if (message >= public_key.p) {
            throw std::runtime_error("Message block exceeds modulus size");
        }

        BigInt k = random_range(kTwo, public_key.p - kTwo, rng);
        BigInt a = mod_exp(public_key.g, k, public_key.p);
        BigInt shared_secret = mod_exp(public_key.y, k, public_key.p);
        BigInt b = mod_mul(shared_secret, message, public_key.p);
        ciphertext.push_back(CipherChunk{a, b, block.second});
    }

    return ciphertext;
}

std::vector<std::uint8_t> decrypt_bytes(const PrivateKey &private_key,
                                        const std::vector<CipherChunk> &ciphertext) {
    std::vector<std::pair<BigInt, std::uint32_t>> decoded_blocks;
    decoded_blocks.reserve(ciphertext.size());

    for (const auto &chunk : ciphertext) {
        BigInt shared_secret = mod_exp(chunk.a, private_key.x, private_key.p);
        BigInt secret_inverse = shared_secret.InverseMod(private_key.p);
        BigInt message = mod_mul(chunk.b, secret_inverse, private_key.p);
        decoded_blocks.emplace_back(message, chunk.len);
    }

    return decode_bytes(decoded_blocks);
}

std::vector<CipherChunk> encrypt(const PublicKey &public_key,
                                 const std::string &plaintext,
                                 CryptoPP::RandomNumberGenerator &rng) {
    std::vector<std::uint8_t> buffer(plaintext.begin(), plaintext.end());
    return encrypt_bytes(public_key, buffer, rng);
}

std::string decrypt(const PrivateKey &private_key,
                    const std::vector<CipherChunk> &ciphertext) {
    auto buffer = decrypt_bytes(private_key, ciphertext);
    return std::string(buffer.begin(), buffer.end());
}

} // namespace elgamal
