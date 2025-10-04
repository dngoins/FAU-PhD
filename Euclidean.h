
#ifndef EUCLIDEAN_H

#define EUCLIDEAN_H

#pragma once
#include <cstdint>
#include <iostream>

#include <stdexcept>
#include <numeric> // for std::gcd
#include <vector>
#include <algorithm> // for std::find
#include <random> // for std::mt19937 and std::uniform_int_distribution

int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return std::abs(a);
}

int lcm(int a, int b) {
    if (a == 0 || b == 0) {
        throw std::invalid_argument("LCM is not defined for zero.");
    }
    return std::abs(a * b) / gcd(a, b);
}

int extended_gcd(int a, int b, int &x, int &y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    int x1, y1;
    int gcd = extended_gcd(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return gcd;
}

int mod_inverse(int a, int m) {
    int x, y;
    int g = extended_gcd(a, m, x, y);
    if (g != 1) {
        throw std::invalid_argument("Inverse doesn't exist");
    } else {
        return (x % m + m) % m;
    }
}

int power_mod(int base, int exponent, int modulus);

// chinese remainder theorem
int chinese_remainder_theorem(const std::vector<int>& a, const std::vector<int>& m) {
    if (a.size() != m.size()) {
        throw std::invalid_argument("Vectors a and m must be of the same size.");
    }
    int prod = 1;
    for (int mod : m) {
        prod *= mod;
    }
    int result = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        int pp = prod / m[i];
        result += a[i] * mod_inverse(pp, m[i]) * pp;
    }
    return result % prod;
}

bool is_prime(int n, int k) {
    if (n <= 1 || n == 4) return false;
    if (n <= 3) return true;

    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dis(2, n - 2);

    for (int i = 0; i < k; i++) {
        int a = dis(gen);
        if (gcd(n, a) != 1) return false;
        if (power_mod(a, n - 1, n) != 1) return false;
    }
    return true;
}

int next_prime(int start) {
    if (start <= 1) return 2;
    int prime = start;
    bool found = false;
    while (!found) {
        prime++;
        if (is_prime(prime, 5))
            found = true;
    }
    return prime;
}

int previous_prime(int start) {
    if (start <= 2) throw std::invalid_argument("No prime number less than 2.");
    int prime = start;
    bool found = false;
    while (!found) {
        prime--;
        if (is_prime(prime, 5))
            found = true;
    }
    return prime;
}

int power_mod(int base, int exponent, int modulus) {
    if (modulus == 1) return 0;
    int result = 1;
    base = base % modulus;
    while (exponent > 0) {
        if (exponent % 2 == 1) // If exponent is odd, multiply base with result
            result = (result * base) % modulus;
        exponent = exponent >> 1; // exponent = exponent / 2
        base = (base * base) % modulus; // Change base to base^2
    }
    return result;
}

namespace number_theory {

// Extended Euclidean algorithm for 64-bit integers.
inline std::int64_t extended_gcd(std::int64_t a, std::int64_t b, std::int64_t &x, std::int64_t &y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }

    std::int64_t x1 = 0;
    std::int64_t y1 = 0;
    std::int64_t gcd = extended_gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - (a / b) * y1;
    return gcd;
}

inline std::uint64_t mod_inverse(std::uint64_t value, std::uint64_t modulus) {
    if (modulus == 0) {
        throw std::invalid_argument("Modulus must be non-zero");
    }

    value %= modulus;
    if (value == 0) {
        throw std::runtime_error("Modular inverse does not exist");
    }

    std::int64_t x = 0;
    std::int64_t y = 0;
    std::int64_t gcd = extended_gcd(static_cast<std::int64_t>(value),
                                     static_cast<std::int64_t>(modulus),
                                     x,
                                     y);
    if (gcd != 1) {
        throw std::runtime_error("Modular inverse does not exist");
    }

    std::int64_t mod = static_cast<std::int64_t>(modulus);
    std::int64_t result = x % mod;
    if (result < 0) {
        result += mod;
    }

    return static_cast<std::uint64_t>(result);
}

} // namespace number_theory

#endif // EUCLIDEAN_H