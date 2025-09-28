# Assignment 01: Computer Data Security
## Due Date: 11:59 PM, Saturday, 9.20.2025

### Author: Dwight Goins


1. ** Which one is the primitive root of 7? **
    - a) 3
    - b) 5
    - c) 2


    - Answer: To find the primitive root of 7, we need to identify a number g such that the powers of g modulo 7 generate all the numbers from 1 to 6.
        - 3^1 mod 7 = 3

        - 3^2 mod 7 = 2

        - 3^3 mod 7 = 6

        - 3^4 mod 7 = 4

        - 3^5 mod 7 = 5

        - 3^6 mod 7 = 1

        - Since all numbers from 1 to 6 are present, the primitive root of 7 is **3**.


2. ** Find an inverse of “23” modulo “120”. Also solve 23x ≡ 3(mod 120) for “x”. (Hint: Use Euclid’s Algorithm & Extended Euclid’s Algorithm) **

    - Answer: To find the inverse of 23 modulo 120, we can use the Extended Euclidean Algorithm.
    
        - First, we apply the Euclidean algorithm to find gcd(23, 120):
            
            - 120 = 5 * 23 + 5 (IV)

            - 23 = 4 * 5 + 3 (III)

            - 5 = 1 * 3 + 2 (II)

            - 3 = 1 * 2 + 1 (I)

            - 2 = 2 * 1 + 0 (Stop here)

            - The gcd is 1, which means that an inverse exists.

        - Now let's backtrack, using the Extended Euclidean Algorithm:
            
            (I) - 1 = 3 - 1 * 2
            
            (II) - 2 = 5 - 1 * 3
            
            (III) - 3 = 23 - 4 * 5
            
            (IV) - 5 = 120 - 5 * 23

            (I) - 1 = 3 - 1 * 2
            - Substitute for 2: 
                - 1 = 3 - 1 * (5 - 1 * 3) = 2 * 3 - 1 * 5
            - Substitute for 3:
                - 1 = 2 * (23 - 4 * 5) - 1 * 5 = 2 * 23 - 9 * 5
            - Substitute for 5:
                - 1 = 2 * 23 - 9 * (120 - 5 * 23) = 47 * 23 - 9 * 120
        - Therefore, the inverse of **23 modulo 120 is 47**.
        
        ** Now solve 23x ≡ 3(mod 120) for “x”. **
        - We can multiply both sides of the equation by the inverse of 23 modulo 120:
            
            - x ≡ 3 * 47 (mod 120)
            
            - x ≡ 141 (mod 120)
            
            - x ≡ 21 (mod 120)
        - Therefore, the solution for x is **21**.

    3. ** Use the Fermat's little theorem to find:  3^52 (mod 11) **

    - Answer: Fermat's Little Theorem states that if p is a prime number and a is an integer not divisible by p, then:

        a^(p-1) ≡ 1 (mod p)

        p = 11 
        a = 3. 

        Since gcd(3, 11) = 1, we can apply the theorem:

        3^(11-1) ≡ 1 (mod 11)
        3^10 ≡ 1 (mod 11)

        Now, we need to find 3^52 (mod 11). We can express 52 in terms of 10:

        52 = 5 * 10 + 2

        Therefore:

        3^52    = 3^(5*10 + 2) 
                = (3^10)^5 * 3^2

        Using Fermat's theorem result:

        (3^10)^5 ≡ 1^5 ≡ 1 (mod 11)

        Now we just need to calculate:

        3^2 = 9

        3^52 ≡ 1 * 9 ≡ 9 (mod 11)

        Therefore, the result is **9**.
    
    
    4. **  What are the prime factorizations of “48” and “60”? Also, find gcd(48, 60) and lcm(48, 60). **

    - Answer: 
        - The prime factorization of 48 is:
        
            48÷2=24 r0
         
            24÷2=12 r0
         
            12÷2=6 r0
         
            6÷2=3 r0
         
            3÷3=1 r0
            
            - 48 = 2^4 * 3^1
        - The prime factorization of 60 is:

            60÷2=30 r0
         
            30÷2=15 r0
         
            15÷3=5 r0
         
            5÷5=1 r0

            - 60 = 2^2 * 3^1 * 5^1

        - To find gcd(48, 60), we take the lowest power of each common prime factor:
         
            - gcd(48, 60) = 2^2 * 3^1 = 4 * 3 = **12**

        - To find lcm(48, 60), we take the highest power of each prime factor present in either number:
         
            - lcm(48, 60) = 2^4 * 3^1 * 5^1 = 16 * 3 * 5 = **240**


    5. ** What is the decimal expansion of (1B6) base 16?  What is the Hexadecimal expansion of “485”? **

    - Answer: 
        - To find the decimal expansion of (1B6) base 16, we can use the formula:
         
            - (1B6)₁₆ = 1×16² + B×16¹ + 6×16⁰
         
            - = 1×256 + 11×16 + 6×1
         
            - = 256 + 176 + 6
         
            - = 438
        
        
        - To find the hexadecimal expansion of “485”, we can use the method of successive division by 16:
         
            - 485 ÷ 16 = 30 remainder 5
         
            - 30 ÷ 16 = 1 remainder 14 (E in hex)
         
            - 1 ÷ 16 = 0 remainder 1
        
        - Reading the remainders from bottom to top, we get:
            - (485)₁₀ = (1E5)₁₆
        
        
    6. ** What sequences of pseudorandom numbers is generated using the linear congruential generator xn+1 = (4xn+1) mod 7 with seed x0 = 3? **

    - Answer: To generate the sequence of pseudorandom numbers using the linear congruential generator formula xn+1 = (4xn + 1) mod 7 with seed x0 = 3, calculate the first few terms of the sequence:

        - x0 = 3
        
        - x1 = (4 * 3 + 1) mod 7 = (12 + 1) mod 7 = 13 mod 7 = 6
        
        - x2 = (4 * 6 + 1) mod 7 = (24 + 1) mod 7 = 25 mod 7 = 4
        
        - x3 = (4 * 4 + 1) mod 7 = (16 + 1) mod 7 = 17 mod 7 = 3
        
        - x4 = (4 * 3 + 1) mod 7 = (12 + 1) mod 7 = 13 mod 7 = 6
        
        - x5 = (4 * 6 + 1) mod 7 = (24 + 1) mod 7 = 25 mod 7 = 4
        
        - x6 = (4 * 4 + 1) mod 7 = (16 + 1) mod 7 = 17 mod 7 = 3


    7. **  Encrypt the message STOP POLLUTION by translating the letters into numbers, applying the given encryption function, and then translating the numbers back into letters: f(x) = (17x + 22) mod 26 **

    - I'm going to use the Ascii values to translate the letters into numbers. Ascii for STOP POLLUTION is:
        
        - S = 83
        - T = 84
        - O = 79
        - P = 80
        - (space) = 32
        - P = 80
        - O = 79
        - L = 76
        - L = 76
        - U = 85
        - T = 84
        - I = 73
        - O = 79
        - N = 78

    - Now, applying the encryption function f(x) = (17x + 22) mod 26 to each number:    

        - For S (83): f(83) = (17*83 + 22) mod 26 = (1411 + 22) mod 26 = 1433 mod 26 = 1
        - For T (84): f(84) = (17*84 + 22) mod 26 = (1428 + 22) mod 26 = 1450 mod 26 = 24
        - For O (79): f(79) = (17*79 + 22) mod 26 = (1343 + 22) mod 26 = 1365 mod 26 = 13
        - For P (80): f(80) = (17*80 + 22) mod 26 = (1360 + 22) mod 26 = 1382 mod 26 = 8
        - For space (32): f(32) = (17*32 + 22) mod 26 = (544 + 22) mod 26 = 566 mod 26 = 18
        - For P (80): f(80) = (17*80 + 22) mod 26 = (1360 + 22) mod 26 = 1382 mod 26 = 8
        - For O (79): f(79) = (17*79 + 22) mod 26 = (1343 + 22) mod 26 = 1365 mod 26 = 13
        - For L (76): f(76) = (17*76 + 22) mod 26 = (1292 + 22) mod 26 = 1314 mod 26 = 14
        - For L (76): f(76) = (17*76 + 22) mod 26 = (1292 + 22) mod 26 = 1314 mod 26 = 14
        - For U (85): f(85) = (17*85 + 22) mod 26 = (1445 + 22) mod 26 = 1467 mod 26 = 9
        - For T (84): f(84) = (17*84 + 22) mod 26 = (1428 + 22) mod 26 =1450 mod 26=24
        - For I (73): f(73) = (17*73 + 22) mod 26 = (1241 + 22) mod 26 = 1263 mod 26 = 15
        - For O (79): f(79) = (17*79 + 22) mod 26 = (1343 + 22) mod 26 = 1365 mod 26 = 13
        - For N (78): f(78) = (17*78 + 22) mod 26 = (1326 + 22) mod 26 = 1348 mod 26 = 24   

        - Now translating the values back into Ascii characters using same encoding as before, Ascii chart/character mapping:
            - 1 = SOH
            - 24 = CAN
            - 13 = CR
            - 8 = BS
            - 18 = DC2
            - 8 = BS
            - 13 = CR
            - 14 = SO
            - 14 = SO
            - 9 = HT
            - 24 = CAN
            - 15 = SI
            - 13 = CR
            - 24 = CAN
        - 
        The encrypted message is in Ascii: **SOH CAN CR BS DC2 BS CR SO SO HT CAN SI CR CAN**


    8. **  Decrypt the following message that were encrypted using the Caesar shift: EOXH MHDQV **

    - Answer: To decrypt a message encrypted using the Caesar shift, we need to shift each letter back by the same number of positions used in the encryption. 

        - The given encrypted message is "EOXH MHDQV". 
        - Assuming a common Caesar shift of 3 (which is often used), we will shift each letter back by 3 positions in the alphabet.

        - E -> B
        - O -> L
        - X -> U
        - H -> E
        - (space)
        - M -> J
        - H -> E
        - D -> A
        - Q -> N
        - V -> S

        - The decrypted message is: **BLUE JEANS**


    9. **  Encrypt the message GRIZZLY BEARS using blocks of five letters and the transposition cipher based on the permutation of {1, 2, 3, 4, 5} with σ(1) = 3, σ(2) = 5, σ(3) = 1, σ(4) = 2 and σ(5) = 4. For this exercise, use the letter X as many times as necessary to fill out the final block of fewer than five letters.**
    
    - Answer: To encrypt the message "GRIZZLY BEARS" using a transposition cipher with the given permutation, we first need to prepare the message by removing spaces and padding it with 'X' to make the length a multiple of 5.

        - The message without spaces is "GRIZZLYBEARS".
        - Add 3 X's to make 15 characters long: "GRIZZLYBEARSXXX".

        - Now we can divide the message into blocks of five letters:
            - Block 1: GRIZZ
            - Block 2: LYBEA
            - Block 3: RSXXX

        - Next, we apply the permutation σ(1) = 3, σ(2) = 5, σ(3) = 1, σ(4) = 2, σ(5) = 4 to each block:
            - For Block 1 (GRIZZ):
                - G (1) -> I (3)
                - R (2) -> Z (5)
                - I (3) -> G (1)
                - Z (4) -> R (2)
                - Z (5) -> Z (4)
                - Result: IGZRR

            - For Block 2 (LYBEA):
                - L (1) -> B (3)
                - Y (2) -> A (5)
                - B (3) -> L (1)
                - E (4) -> Y (2)
                - A (5) -> E (4)
                - Result: BALYE

            - For Block 3 (RSXXX):
                - R (1) -> X (3)
                - S (2) -> X (5)
                - X (3) -> R (1)
                - X (4) -> S (2)
                - X (5) -> X (4)
                - Result: XXRSX

        - Combining the results from each block to get the encrypted message:
            - Encrypted message: **IGZRR BALYE XXRSX**

