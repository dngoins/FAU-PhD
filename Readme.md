# Hybrid AES + ElGamal Cryptography

This C++17 project combines a custom AES-128 implementation with ElGamal public-key encryption (via Crypto++) to form a reusable hybrid cryptography toolkit. A small command-line demo walks through generating keys, encrypting text, and recovering the plaintext.

## Highlights

- Static library `crypto_core` exposes modular AES and ElGamal components plus a `HybridCrypto` façade for key management and payload encryption.
- AES uses CBC mode with PKCS#7 padding; 16-byte session keys are randomly generated and can be exported/imported in hex.
- ElGamal keys enforce a minimum 256-bit modulus and leverage Crypto++ for safe-prime generation and modular arithmetic.
- Session keys are wrapped with ElGamal so only the holder of the private key can decrypt the symmetric material.
- A menu-driven demo (`hybrid_demo`) illustrates the full flow and prints formatted shares (wrapped key, IV, ciphertext) for inspection.

## Requirements

- Windows with Visual Studio 2022 MSVC toolchain (CMake auto-detects it).
- CMake 3.16 or newer.
- Git so CMake can fetch the `cryptopp-cmake` wrapper.

CMake downloads and builds Crypto++ automatically—no extra setup is required.

## Building

```pwsh
# From the repository root
cmake -S . -B build
cmake --build build --target hybrid_demo --config Release
# Optional Debug build
cmake --build build --target hybrid_demo --config Debug
```

`crypto_core.lib` and `hybrid_demo.exe` are emitted under `build/<config>/`.

## Using the Hybrid Demo

Launch the executable and follow the prompts. Typical first-run sequence:

```pwsh
PS C:\source\repo\github\dngoins\FAU-PhD> .\build\Debug\hybrid_demo.exe
=== Hybrid Cryptography Demo ===
 1) Generate ElGamal key pair
 2) Set public key from hex
 3) Set private key from hex
 4) Generate new AES session key
 5) Set session key from hex
 6) View current keys
 7) Encrypt message
 8) Decrypt last ciphertext
 9) Exit
Select option: 1
Enter key size in bits (>=256): 256
Generated new ElGamal key pair.

Select option: 4
Generated new AES session key.

Select option: 7
Enter plaintext message: Hello hybrid world!

=== Ciphertext Summary ===
Wrapped session key chunks: 1
  Chunk 0 (len=16):
    a = ...
    b = ...
IV: ...
AES-CBC ciphertext: ...
Encryption complete.

Select option: 8
Recovered plaintext: Hello hybrid world!
```

### Importing Existing Keys

If you already have key material, choose options 2, 3, and 5 to paste hex-encoded values exported from a previous run. The demo validates formatting and rejects inconsistent key sets.

### Programmatic Use

Library consumers can include `hybrid_crypto.h` and interact with the `HybridCrypto` class directly:

```cpp
#include "hybrid_crypto.h"

HybridCrypto crypto;
crypto.generate_elgamal_keys(256);
crypto.generate_session_key();

const auto ciphertext = crypto.encrypt("Sensitive payload");
const auto recovered = crypto.decrypt(ciphertext);
```

See `hybrid_demo.cpp` for a full example including hex serialization helpers.

## Legacy ElGamal Demo

The original standalone ElGamal driver (`elgamal.exe`) remains available for exploring raw public-key operations. Build it with `cmake --build build --target elgamal --config Release` if needed.

## License

This project is provided as a final assignment for FAU course 6730 Computer Data Security (Cryptography) for educational purposes. Consult local regulations before distributing cryptographic software internationally.
