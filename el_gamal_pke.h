
/*
Author: Dwight Goins
Course: 6730 Computer Data Security (Cryptography)
Date: 10.04.2025

Summary:
    Implementation the ElGamal Public-Key Encryption scheme with C++17. This program requests the “key size” from the user in terms of number of bits (for instance, 64, 128, etc). Based on the size, it will use Fermat algorithm to define the large prime number. The program will initialize a pair of public and private keys. For the computations, it will utilize the Square-and Multiply algorithm. 
    
    The program will get a plaintext from the user to perform encryption (generating the ciphertext from the plaintext) and decryption (generating the original plaintext from the ciphertext).
    
*/

#ifndef ELGAMAL_PKE_H
#define ELGAMAL_PKE_H
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <cryptopp/integer.h>

namespace CryptoPP {
class RandomNumberGenerator;
}

namespace elgamal {

using BigInt = CryptoPP::Integer;

struct PublicKey {
    BigInt p;  // Large prime modulus
    BigInt g;  // Generator of multiplicative group modulo p
    BigInt y;  // g^x mod p
};

struct PrivateKey {
    BigInt p;  // Matches public modulus
    BigInt g;  // Matches generator
    BigInt x;  // Secret exponent
};

struct CipherChunk {
    BigInt a;          // g^k mod p
    BigInt b;          // y^k * m mod p
    std::uint32_t len; // Number of plaintext bytes encoded in this chunk
};

std::pair<PublicKey, PrivateKey> generate_keys(std::size_t bit_length,
                                               CryptoPP::RandomNumberGenerator &rng);

std::vector<CipherChunk> encrypt(const PublicKey &public_key,
                                 const std::string &plaintext,
                                 CryptoPP::RandomNumberGenerator &rng);

std::string decrypt(const PrivateKey &private_key,
                    const std::vector<CipherChunk> &ciphertext);

void run_cli();

} // namespace elgamal

#endif // ELGAMAL_PKE_H