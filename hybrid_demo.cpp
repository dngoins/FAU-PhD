#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>

#include <cryptopp/osrng.h>

#include "crypto_utils.h"
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <cryptopp/osrng.h>

#include "crypto_utils.h"
#include "hybrid_crypto.h"

namespace {

std::string prompt_line(const std::string &prompt) {
    std::cout << prompt;
    std::string line;
    std::getline(std::cin, line);
    return line;
}

void wait_for_enter() {
    std::cout << "\nPress Enter to continue...";
    std::string line;
    std::getline(std::cin, line);
}

void print_keys(const hybrid::HybridCryptoService &service) {
    std::cout << "\n=== Key Material ===\n";
    try {
        const auto [p_hex, g_hex, y_hex] = service.public_key_hex();
        std::cout << "Public modulus (p): " << p_hex << '\n';
        std::cout << "Generator (g): " << g_hex << '\n';
        std::cout << "Public key (y): " << y_hex << '\n';
    } catch (const std::exception &ex) {
        std::cout << "Public key unavailable: " << ex.what() << '\n';
    }

    try {
        const auto [p_hex, g_hex, x_hex] = service.private_key_hex();
        std::cout << "Private modulus (p): " << p_hex << '\n';
        std::cout << "Generator (g): " << g_hex << '\n';
        std::cout << "Private key (x): " << x_hex << '\n';
    } catch (const std::exception &ex) {
        std::cout << "Private key unavailable: " << ex.what() << '\n';
    }

    try {
        std::cout << "Session key (AES-128): " << service.session_key_hex() << '\n';
    } catch (const std::exception &ex) {
        std::cout << "Session key unavailable: " << ex.what() << '\n';
    }
}

void display_ciphertext(const hybrid::HybridCiphertext &ciphertext) {
    std::cout << "\n=== Ciphertext Summary ===\n";
    std::cout << "Wrapped session key chunks: " << ciphertext.wrapped_session_key.size() << '\n';
    for (std::size_t i = 0; i < ciphertext.wrapped_session_key.size(); ++i) {
        const auto &chunk = ciphertext.wrapped_session_key[i];
        std::cout << "  Chunk " << i << " (len=" << chunk.len << "):\n";
        std::cout << "    a = " << crypto::utils::bigint_to_hex(chunk.a) << '\n';
        std::cout << "    b = " << crypto::utils::bigint_to_hex(chunk.b) << '\n';
    }
    std::cout << "IV: " << crypto::utils::bytes_to_hex(ciphertext.iv, true) << '\n';
    std::cout << "AES-CBC ciphertext: " << crypto::utils::bytes_to_hex(ciphertext.ciphertext, true) << '\n';
}

int parse_choice(const std::string &input) {
    try {
        return std::stoi(input);
    } catch (...) {
        return -1;
    }
}

} // namespace

int main() {
    CryptoPP::AutoSeededRandomPool rng;
    hybrid::HybridCryptoService service;
    std::optional<hybrid::HybridCiphertext> last_ciphertext;

    while (true) {
        std::cout << "\n=== Hybrid Cryptography Demo ===\n";
        std::cout << " 1) Generate ElGamal key pair\n";
        std::cout << " 2) Set public key from hex\n";
        std::cout << " 3) Set private key from hex\n";
        std::cout << " 4) Generate new AES session key\n";
        std::cout << " 5) Set session key from hex\n";
        std::cout << " 6) View current keys\n";
        std::cout << " 7) Encrypt message\n";
        std::cout << " 8) Decrypt last ciphertext\n";
        std::cout << " 9) Exit\n";

        int choice = parse_choice(prompt_line("Select option: "));
        std::cout << '\n';

        try {
            switch (choice) {
            case 1: {
                const std::string bit_str = prompt_line("Enter key size in bits (>=256): ");
                const std::size_t bits = static_cast<std::size_t>(std::stoul(bit_str));
                service.generate_key_pair(bits, rng);
                std::cout << "Generated new ElGamal key pair." << '\n';
                break;
            }
            case 2: {
                const std::string p_hex = prompt_line("Enter public modulus p (hex): ");
                const std::string g_hex = prompt_line("Enter generator g (hex): ");
                const std::string y_hex = prompt_line("Enter public key y (hex): ");
                service.set_public_key_from_hex(p_hex, g_hex, y_hex);
                std::cout << "Updated public key." << '\n';
                break;
            }
            case 3: {
                const std::string p_hex = prompt_line("Enter private modulus p (hex): ");
                const std::string g_hex = prompt_line("Enter generator g (hex): ");
                const std::string x_hex = prompt_line("Enter private key x (hex): ");
                service.set_private_key_from_hex(p_hex, g_hex, x_hex);
                std::cout << "Updated private key." << '\n';
                break;
            }
            case 4: {
                service.generate_session_key(rng);
                std::cout << "Generated new AES session key." << '\n';
                break;
            }
            case 5: {
                const std::string key_hex = prompt_line("Enter AES session key (32 hex chars): ");
                service.set_session_key_from_hex(key_hex);
                std::cout << "Updated AES session key." << '\n';
                break;
            }
            case 6: {
                print_keys(service);
                break;
            }
            case 7: {
                const std::string message = prompt_line("Enter plaintext message: ");
                const auto plaintext_bytes = crypto::utils::string_to_bytes(message);
                auto ciphertext = service.encrypt(plaintext_bytes, rng);
                display_ciphertext(ciphertext);
                last_ciphertext = std::move(ciphertext);
                std::cout << "Encryption complete." << '\n';
                break;
            }
            case 8: {
                if (!last_ciphertext) {
                    std::cout << "No ciphertext available. Encrypt a message first." << '\n';
                    break;
                }
                const auto recovered_bytes = service.decrypt(*last_ciphertext);
                std::cout << "Recovered plaintext: "
                          << crypto::utils::bytes_to_string(recovered_bytes) << '\n';
                break;
            }
            case 9:
                std::cout << "Exiting." << std::endl;
                return 0;
            default:
                std::cout << "Invalid selection. Please choose a valid option." << '\n';
                break;
            }
        } catch (const std::exception &ex) {
            std::cout << "Error: " << ex.what() << '\n';
        }

        wait_for_enter();
    }
}