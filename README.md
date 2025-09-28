# AES Demonstration Program

## Overview

- Implements an educational AES-128 encryption/decryption flow over 16-byte blocks.
- Uses a custom SubBytes stage derived from the affine transform `7 · x^61 + 99 (mod 2^61 − 1)`.
- Converts user-supplied key and plaintext strings into byte-oriented state matrices, encrypts, then decrypts to verify round-trip correctness.

## Program Layout

- `AES.cpp` – full implementation (state helpers, key schedule, round functions, CLI demo).
- `AES.h` – public `AES128` interface with block and key type aliases.
- `Euclidean.h` – number-theory helpers reused by modular arithmetic.

## Build Instructions

- Requires a C++17-capable compiler (tested with `g++`).
- From the repository root:

```pwsh
# Windows PowerShell
cd C:\source\repo\github\dngoins\FAU-PhD
g++ AES.cpp -std=c++17 -O2 -o AES.exe
```

Adjust the output name as needed for your platform.

## Running the Demo

1. Execute the compiled binary (`AES.exe` on Windows, `./AES` on Unix-like systems).
2. When prompted, enter up to 16 characters for the encryption key.
3. Enter up to 16 characters of plaintext to encrypt.
4. The program prints the ciphertext in hexadecimal and the decrypted plaintext for verification.

Example session:

```text
Enter up to 16 characters for the AES key: testkey123456789
Enter up to 16 characters of plaintext: hello world!!!
Ciphertext (hex): 4e 4b 0f 7a 74 60 1a 18 15 38 91 ea 0f 71 5e 2c 
Recovered plaintext: hello world!!!
```

## Implementation Notes

- Key expansion generates 11 round keys (initial plus 10 rounds) exactly as expected for AES-128.
- The custom S-box is built at runtime by ranking transformed byte values to guarantee a bijective mapping.
- State helpers (`bytes_to_state`, `state_to_bytes`) keep the 4×4 byte matrix in sync with linear buffers.
- Only single-block ECB-style encrypt/decrypt is supported; CBC modes and external padding are intentionally left for future work.
- Inputs shorter than 16 bytes are implicitly padded with zero bytes; longer inputs are truncated.

## Next Ideas

- Add standard AES S-box support to compare results with the NIST specification.
- Implement block-chaining modes (CBC, CTR, GCM) and PKCS#7 padding for multi-block messages.
- Introduce automated tests that confirm known-answer vectors and guard against regressions.
