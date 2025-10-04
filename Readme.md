# ElGamal Public-Key Encryption Demo

This C++17 command-line application demonstrates the full ElGamal public-key encryption flow using the Crypto++ library for big integer arithmetic, safe-prime generation, and cryptographic randomness. The program guides you through selecting a key size, generating a key pair, encrypting a plaintext message, and verifying successful decryption.

## Features

- Menu-driven key size selection ranging from 32-bit demo keys up to very large 65,536-bit keys, along with estimated key-generation times for every choice.
- Automatic safe-prime generation via Crypto++ `PrimeAndGenerator`.
- Encryption and decryption implemented with Crypto++ modular arithmetic (`CryptoPP::Integer`).
- Plaintext chunking sized to the modulus so arbitrary-length UTF-8 strings are supported.
- Hex-formatted ciphertext output and automatic verification that decrypted text matches the original input.
- Estimated time-to-completion feedback for long key-generation runs (4096 bits and higher).

## Requirements

- Windows with Visual Studio 2022 MSVC toolchain (CMake will auto-detect).
- CMake 3.16 or newer.
- Git (required so CMake can fetch the `cryptopp-cmake` wrapper).

No manual Crypto++ installation is necessary; CMake fetches and builds it automatically through `FetchContent`.

## Building

```pwsh
# From the repository root
cmake -S . -B build
cmake --build build --config Release
# Optional Debug build
cmake --build build --config Debug
```

Executables are emitted to `build/Release/elgamal.exe` (or `build/Debug/elgamal.exe`).

## Running the Demo

```pwsh
PS C:\source\repo\github\dngoins\FAU-PhD> .\build\Release\elgamal.exe
ElGamal Public-Key Encryption (C++17)
--------------------------------------------------
Choose key size:
  1) 32-bit (~a few seconds)
  2) 64-bit (~a few seconds)
  3) 128-bit (~a few seconds)
  4) 256-bit (~a few seconds)
  5) 512-bit (~a few seconds)
  6) 1024-bit (~a few seconds)
  7) 2048-bit (~a few seconds)
  8) 4096-bit (~45-120 seconds)
  9) 8192-bit (~3-6 minutes)
 10) 16384-bit (~15-30 minutes)
 11) 32768-bit (~1-2 hours)
 12) 65536-bit (~4-8 hours)
Selection: 4
Generating keys ... this may take a moment.
Key generation completed in 87 ms (~0.09 s)
Public modulus (p): 606225...
Generator (g): 5
Public key (y): 245301...
Private key (x): 112233...

Enter plaintext message: Hello, ElGamal!

Ciphertext pairs (a, b):
  Block 0 (len=14):
    a = 356902...
    b = 140550...

Ciphertext (hex): a=50d4...|b=224f...

Recovered plaintext: Hello, ElGamal!
Verification: success
```

> **Note:** Timing grows rapidly for large primes. Keys ≥4096 bits can take minutes or more to generate on typical desktops. The program displays an estimated range before starting the computation so you can decide whether to proceed.

## License

This project is provided for educational purposes. Consult local regulations before distributing cryptographic software internationally.
