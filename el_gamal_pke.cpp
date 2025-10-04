#include "el_gamal_pke.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <cryptopp/modarith.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>

namespace elgamal {

namespace {

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Integer;
using CryptoPP::PrimeAndGenerator;
using CryptoPP::SecByteBlock;

const Integer kTwo = 2;
const Integer kOne = 1;

std::string keygen_eta(std::size_t bit_length) {
    switch (bit_length) {
    case 4096:
        return "~45-120 seconds";
    case 8192:
        return "~3-6 minutes";
    case 16384:
        return "~15-30 minutes";
    case 32768:
        return "~1-2 hours";
    case 65536:
        return "~4-8 hours";
    default:
        return "~a few seconds";
    }
}

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
encode_plaintext(const std::string &plaintext, std::size_t block_bytes) {
    std::vector<std::pair<BigInt, std::uint32_t>> encoded;
    encoded.reserve((plaintext.size() / block_bytes) + 1);

    if (plaintext.empty()) {
        encoded.emplace_back(CryptoPP::Integer::Zero(), 0U);
        return encoded;
    }

    std::size_t index = 0;
    while (index < plaintext.size()) {
        std::uint32_t len = 0;
        std::size_t chunk_len = std::min(block_bytes, plaintext.size() - index);
        len = static_cast<std::uint32_t>(chunk_len);
        BigInt value(reinterpret_cast<const CryptoPP::byte *>(plaintext.data() + index), len);
        encoded.emplace_back(value, len);
        index += chunk_len;
    }

    return encoded;
}

std::string decode_plaintext(const std::vector<std::pair<BigInt, std::uint32_t>> &blocks) {
    std::string result;
    std::size_t total_bytes = 0;
    for (const auto &entry : blocks) {
        total_bytes += entry.second;
    }
    result.reserve(total_bytes);

    for (const auto &entry : blocks) {
        const BigInt &value = entry.first;
        std::uint32_t len = entry.second;
        if (len == 0U) {
            continue;
        }

        std::string chunk(len, '\0');
        value.Encode(reinterpret_cast<CryptoPP::byte *>(&chunk[0]), len);
        result += chunk;
    }

    return result;
}

std::tuple<BigInt, BigInt, BigInt> generate_safe_prime_triplet(std::size_t bit_length,
                                                               CryptoPP::RandomNumberGenerator &rng) {
    if (bit_length < 32) {
        throw std::invalid_argument("Bit length must be at least 32 bits");
    }

    PrimeAndGenerator generator;
    generator.Generate(1, rng, static_cast<int>(bit_length), static_cast<int>(bit_length - 1));
    return {generator.Prime(), generator.SubPrime(), generator.Generator()};
}

std::string bigint_to_hex(const BigInt &value) {
    if (value.IsZero()) {
        return "00";
    }

    std::size_t byte_count = value.MinEncodedSize();
    SecByteBlock buffer(byte_count);
    value.Encode(buffer, buffer.size());

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < buffer.size(); ++i) {
        oss << std::setw(2) << static_cast<int>(buffer[i]);
    }

    return oss.str();
}

} // namespace

std::pair<PublicKey, PrivateKey> generate_keys(std::size_t bit_length,
                                               CryptoPP::RandomNumberGenerator &rng) {
    auto [p, q, g] = generate_safe_prime_triplet(bit_length, rng);

    BigInt secret = random_range(kTwo, p - kTwo, rng);
    BigInt y = mod_exp(g, secret, p);

    PublicKey pub{p, g, y};
    PrivateKey priv{p, g, secret};
    return {pub, priv};
}

std::vector<CipherChunk> encrypt(const PublicKey &public_key,
                                 const std::string &plaintext,
                                 CryptoPP::RandomNumberGenerator &rng) {
    std::size_t block_bytes = determine_block_size(public_key.p);
    auto encoded_blocks = encode_plaintext(plaintext, block_bytes);

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

std::string decrypt(const PrivateKey &private_key,
                    const std::vector<CipherChunk> &ciphertext) {
    std::vector<std::pair<BigInt, std::uint32_t>> decoded_blocks;
    decoded_blocks.reserve(ciphertext.size());

    for (const auto &chunk : ciphertext) {
        BigInt shared_secret = mod_exp(chunk.a, private_key.x, private_key.p);
    BigInt secret_inverse = shared_secret.InverseMod(private_key.p);
        BigInt message = mod_mul(chunk.b, secret_inverse, private_key.p);
        decoded_blocks.emplace_back(message, chunk.len);
    }

    return decode_plaintext(decoded_blocks);
}

void run_cli() {
    std::cout << "ElGamal Public-Key Encryption (C++17)" << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "Choose key size:" << std::endl;
    std::cout << "  1) 32-bit" << std::endl;
    std::cout << "  2) 64-bit" << std::endl;
    std::cout << "  3) 128-bit" << std::endl;
    std::cout << "  4) 256-bit" << std::endl;
    std::cout << "  5) 512-bit" << std::endl;
    std::cout << "  6) 1024-bit" << std::endl;
    std::cout << "  7) 2048-bit" << std::endl;
    std::cout << "  8) 4096-bit" << std::endl;
    std::cout << "  9) 8192-bit" << std::endl;
    std::cout << " 10) 16384-bit" << std::endl;
    std::cout << " 11) 32768-bit" << std::endl;
    std::cout << " 12) 65536-bit" << std::endl;
    std::cout << "Selection: " << std::flush;

    int selection = 0;
    if (!(std::cin >> selection)) {
        throw std::runtime_error("Failed to parse selection");
    }

    std::size_t bit_length = 0;
    switch (selection) {
    case 1:
        bit_length = 32;
        break;
    case 2:
        bit_length = 64;
        break;
    case 3:
        bit_length = 128;
        break;
    case 4:
        bit_length = 256;
        break;
    case 5:
        bit_length = 512;
        break;
    case 6:
        bit_length = 1024;
        break;
    case 7:
        bit_length = 2048;
        break;
    case 8:
        bit_length = 4096;
        break;
    case 9:
        bit_length = 8192;
        break;
    case 10:
        bit_length = 16384;
        break;
    case 11:
        bit_length = 32768;
        break;
    case 12:
        bit_length = 65536;
        break;
    default:
        throw std::runtime_error("Invalid key size selection");
    }

    if (bit_length >= 4096) {
        std::cout << "Estimated generation time for " << bit_length << "-bit keys: "
                  << keygen_eta(bit_length) << ".\n";
    }

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    CryptoPP::AutoSeededRandomPool key_rng;

    std::cout << "Generating keys ... this may take a moment.\n";
    auto start = std::chrono::steady_clock::now();
    auto [public_key, private_key] = generate_keys(bit_length, key_rng);
    auto end = std::chrono::steady_clock::now();

    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "Key generation completed in " << duration_ms << " ms\n";

    std::cout << "Public modulus (p): " << public_key.p << "\n";
    std::cout << "Generator (g): " << public_key.g << "\n";
    std::cout << "Public key (y): " << public_key.y << "\n";
    std::cout << "Private key (x): " << private_key.x << "\n";

    std::cout << "\nEnter plaintext message: " << std::flush;
    std::string plaintext;
    std::getline(std::cin, plaintext);

    CryptoPP::AutoSeededRandomPool enc_rng;
    auto ciphertext = encrypt(public_key, plaintext, enc_rng);

    std::cout << "\nCiphertext pairs (a, b):\n";
    for (std::size_t i = 0; i < ciphertext.size(); ++i) {
        const auto &chunk = ciphertext[i];
        std::cout << "  Block " << i << " (len=" << chunk.len << "):\n";
        std::cout << "    a = " << chunk.a << "\n";
        std::cout << "    b = " << chunk.b << "\n";
    }

    std::ostringstream cipher_summary;
    for (std::size_t i = 0; i < ciphertext.size(); ++i) {
        if (i != 0) {
            cipher_summary << " | ";
        }
        cipher_summary << "a=" << bigint_to_hex(ciphertext[i].a)
                       << ",b=" << bigint_to_hex(ciphertext[i].b);
    }

    std::cout << "\nCiphertext (hex): " << cipher_summary.str() << "\n";

    auto recovered = decrypt(private_key, ciphertext);
    std::cout << "\nRecovered plaintext: " << recovered << "\n";

    if (recovered == plaintext) {
        std::cout << "Verification: success" << std::endl;
    } else {
        std::cout << "Verification: failed" << std::endl;
    }
}

} // namespace elgamal

int main() {
    try {
        elgamal::run_cli();
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
