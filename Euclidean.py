def gcd(a, b):
    x= abs(a)
    y= abs(b)
    while y !=  0:
        remainder = x % y
        x = y
        y = remainder
    return x


def lcm(a, b):
    return abs(a * b) // gcd(a, b)

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Inverse doesn't exist")
    else:
        return x % m
    
def chinese_remainder_theorem(a1, n1, a2, n2):
    gcd, m1, m2 = extended_gcd(n1, n2)
    if (a1 - a2) % gcd != 0:
        raise ValueError("No solutions exist")
    lcm = (n1 * n2) // gcd
    x = (a1 * m2 * n2 + a2 * m1 * n1) // gcd
    return x % lcm, lcm

def prime_factors(n):
    factors = []
    for i in range(2, int(n**0.5) + 1):
        while n % i == 0:
            factors.append(i)
            n //= i
    if n > 1:
        factors.append(n)
    return factors

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True 

def next_prime(n):
    if n <= 1:
        return 2
    prime = n
    found = False
    while not found:
        prime += 1
        if is_prime(prime):
            found = True
    return prime

def prev_prime(n):
    if n <= 2:
        return None
    prime = n
    found = False
    while not found:
        prime -= 1
        if is_prime(prime):
            found = True
    return prime    


