# 🔐 DES and Triple DES — Data Encryption Standard

> A from-zero guide to DES and Triple DES (3DES / TDEA): what encryption and block ciphers are, how DES works step by step with every table of the standard, a complete worked example of all 16 rounds, why Triple DES exists, how longer messages are padded and chained (ECB, CBC, IV), and where both still run in payment systems — PIN blocks, key encryption, key check values and the Retail MAC.

> [!NOTE]
> **Prerequisites:** DES moves **bits** and mixes them with **XOR**. If you are not yet at home with hexadecimal, bits and bytes, read [Base Conversion](https://github.com/Mr-Alireza82/Base-Conversion) first; for XOR and why it can undo itself, read [XOR — Exclusive OR](https://github.com/Mr-Alireza82/XOR). Links like *[XOR §6]* point to their sections.

---

## Table of Contents

**Part A — Understanding (no math)**

1. [What Is Encryption?](#1-what-is-encryption)
2. [Symmetric Keys and Block Ciphers](#2-symmetric-keys-and-block-ciphers)
3. [The Two Tricks: Substitute and Shuffle](#3-the-two-tricks-substitute-and-shuffle)
4. [The Feistel Idea — Decryption for Free](#4-the-feistel-idea--decryption-for-free)
5. [A Short History](#5-a-short-history)

**Part B — The Algorithm**

6. [Overview](#6-overview)
7. [The Key Schedule](#7-the-key-schedule)
8. [Initial and Final Permutation](#8-initial-and-final-permutation)
9. [The Round Function f](#9-the-round-function-f)
10. [Sixteen Rounds](#10-sixteen-rounds)
11. [Decryption](#11-decryption)

**Part C — A Complete Worked Example**

12. [The Round Keys](#12-the-round-keys)
13. [Round 1 in Detail](#13-round-1-in-detail)
14. [All Sixteen Rounds](#14-all-sixteen-rounds)
15. [The Result — and the Avalanche](#15-the-result--and-the-avalanche)

**Part D — Triple DES**

16. [Why Not Double DES?](#16-why-not-double-des)
17. [Triple DES — Encrypt, Decrypt, Encrypt](#17-triple-des--encrypt-decrypt-encrypt)

**Part E — Longer Messages: Padding, Modes and the IV**

18. [Padding](#18-padding)
19. [ECB — Every Block Alone](#19-ecb--every-block-alone)
20. [CBC — Blocks in a Chain](#20-cbc--blocks-in-a-chain)

**Part F — DES in Payment Systems**

21. [Where DES Still Runs](#21-where-des-still-runs)
22. [Key Check Value](#22-key-check-value)
23. [Parity Bits and Weak Keys](#23-parity-bits-and-weak-keys)

**Part G — In Code**

24. [Two Ways: Standard and Paper](#24-two-ways-standard-and-paper)
25. [Using the Library](#25-using-the-library)

**Part H — Reference**

26. [Cheat Sheet](#26-cheat-sheet)
27. [Practice](#27-practice)
28. [Conclusion](#28-conclusion)

---

# Part A — Understanding (no math)

## 1. What Is Encryption?

You want to send a note to a friend across a crowded room. Everyone can see the note while it travels. So you put it in a box, lock the box with a padlock, and pass the box. Only your friend has the same key.

That is encryption:

| Word | In the story | In computing |
|---|---|---|
| **Plaintext** | The note | The readable data, e.g. a PIN block |
| **Key** | The padlock key | A secret string of bits |
| **Encryption** | Locking the box | Turning plaintext into ciphertext with the key |
| **Ciphertext** | The locked box | Data that looks random without the key |
| **Decryption** | Unlocking | Turning ciphertext back into plaintext with the key |

One rule from 1883 (Kerckhoffs's principle) still holds: **the method may be public; only the key is secret.** Everyone knows how a padlock works, and that doesn't help anyone open yours. DES is completely public — every table is printed in this article — and is still only breakable by trying keys.

---

## 2. Symmetric Keys and Block Ciphers

**Symmetric** means the **same key** locks and unlocks, like a house key. Both the terminal and the bank's HSM must hold the same secret key. (The other family, *asymmetric* or *public-key* cryptography like RSA, uses a pair of different keys. It is not covered here.)

A **block cipher** encrypts data in fixed-size pieces called **blocks**. DES is a block cipher with:

| Property | Size |
|---|---|
| Block | 64 bits = 8 bytes = 16 hex digits |
| Key | 64 bits stored, of which **56** are used |
| Rounds | 16 |

Think of a machine with exactly 8 slots: you insert exactly 8 bytes, turn the handle, and get exactly 8 different-looking bytes out. Not 7, not 9.

So how do you encrypt a 10-byte message? You first **pad** it to a multiple of 8 and then feed it block by block using a **mode of operation** (ECB, CBC, …). Padding and modes are built *around* DES; the [Retail MAC article](https://github.com/Mr-Alireza82/ANSI-X9.19-Retail-MAC-Algorithm) shows both. This article is about what happens to **one** block.

---

## 3. The Two Tricks: Substitute and Shuffle

Every good block cipher does only two simple things, over and over. Claude Shannon named them in 1949:

### Confusion — substitute

Replace each small piece by another through a secret-looking table, like a child's code book: *A → Q, B → W, C → E …*. In DES these tables are the eight **S-boxes**. They are the only non-linear part, the real "lock".

### Diffusion — shuffle

Move the pieces to different positions, like shuffling a deck of cards, so that each piece of output depends on many pieces of input. In DES these are the **permutations** (E, P, IP, FP, PC-1, PC-2).

A single substitute-and-shuffle is weak. Repeated 16 times, with a different part of the key mixed in each time, every output bit ends up depending on **every** input bit and **every** key bit.

### The avalanche

The result is the **avalanche effect**: change one input bit and about half of the output bits change. From the worked example in [§15](#15-the-result--and-the-avalanche):

| Plaintext | Ciphertext |
|---|---|
| `0123456789ABCDEF` | `85E813540F0AB405` |
| `0123456789ABCDEE` (last bit flipped) | `28378E295BE22A84` |

**One** input bit changed; **37** of the 64 output bits changed. Nothing in the second ciphertext hints at the first.

---

## 4. The Feistel Idea — Decryption for Free

Here is the problem with "substitute and shuffle": to decrypt, you would need to run every step backwards, so every step would have to be reversible. Designing a strong function that can also be run backwards is hard.

Horst Feistel (IBM, early 1970s) found a way around it:

1. Cut the block into two halves: **Left** and **Right**.
2. Put the Right half through a scrambling function **f** together with a part of the key.
3. **XOR** the scrambled result into the Left half.
4. **Swap** the halves.
5. Repeat.

```text
      L            R
      │            │
      │      ┌─────┤
      │      │     │
      │   ┌──▼──┐  │
      │   │  f  │◄─┼─── round key
      │   └──┬──┘  │
      ▼      │     │
     XOR ◄───┘     │
      │            │
      └─────┐ ┌────┘
            ╳            swap
      ┌─────┘ └────┐
      ▼            ▼
   new L        new R
```

Why this is clever: the Right half is **copied unchanged** into the next round. So anyone who knows the key can compute **f** again from it and **XOR it out** — because XOR with the same value twice gives the original *[[XOR §6](https://github.com/Mr-Alireza82/XOR#6-the-five-properties)]*.

> **f never has to be reversed.** It can be as messy and one-way as you like. Decryption is the same machine, with the round keys fed in the opposite order.

---

## 5. A Short History

| Year | Event |
|---|---|
| 1973–74 | The US National Bureau of Standards (now NIST) asks for a public encryption standard. IBM submits *Lucifer*, a Feistel cipher. |
| 1977 | Published as **DES**, FIPS PUB 46, with the key cut to 56 bits and S-boxes revised with the NSA. |
| 1990s | Banking adopts DES for PINs, keys and MACs (ANSI X9 standards). |
| 1998 | The EFF builds *Deep Crack* and finds a DES key by trying all keys in **56 hours**. |
| 1999 | **Triple DES** added to the standard (FIPS 46-3). A DES key is broken in 22 hours. |
| 2001 | AES (FIPS 197) becomes the modern standard. |
| 2005 | NIST withdraws single DES. |
| 2023 | NIST disallows Triple DES for new encryption after 31 December 2023 (SP 800-131A Rev. 2). |

> [!WARNING]
> **Single DES is broken**: 56 bits can be searched by anyone with rented computing power. **Triple DES is deprecated**. Both are covered here because a large part of the world's payment infrastructure (terminals, HSMs, ISO 8583 switches, EMV cards) still runs on Triple DES while it migrates to AES. Learn them to maintain and integrate those systems — never choose them for a new design.

---

# Part B — The Algorithm

## 6. Overview

| Symbol | Meaning | Size |
|---|---|---|
| $P$ | Plaintext block | 64 bits |
| $K$ | Key | 64 bits (56 used) |
| $K_1 \dots K_{16}$ | Round keys | 48 bits each |
| $L_i, R_i$ | Left and right half after round $i$ | 32 bits each |
| $f$ | Round function | 32 bits in → 32 bits out |
| $\oplus$ | XOR *[[XOR](https://github.com/Mr-Alireza82/XOR)]* | — |
| $C$ | Ciphertext block | 64 bits |

```text
          64-bit key                        64-bit plaintext block
               │                                    │
            PC-1 (64 → 56)                     IP (shuffle)
               │                                    │
          C0 ‖ D0 (28 + 28)                    L0 ‖ R0 (32 + 32)
               │                                    │
   ┌───────────┤                          ┌─────────┤
   │   rotate left 1 or 2                 │   round 1:  L1 = R0
   │   PC-2 (56 → 48) ────── K1 ─────────►│             R1 = L0 ⊕ f(R0, K1)
   │           │                          │         │
   │   rotate, PC-2 ──────── K2 ─────────►│   round 2
   │           ⋮                          │         ⋮
   │   rotate, PC-2 ──────── K16 ────────►│   round 16
   └───────────┘                          └─────────┤
                                                    │
                                         R16 ‖ L16 (swap)
                                                    │
                                              FP = IP⁻¹
                                                    │
                                          64-bit ciphertext
```

The whole of DES in three lines:

$$L_0 \parallel R_0 = IP(P)$$

$$\boxed{L_i = R_{i-1} \qquad R_i = L_{i-1} \oplus f(R_{i-1}, K_i) \qquad i = 1 \dots 16}$$

$$C = FP(R_{16} \parallel L_{16})$$

### How to read the tables

All tables below come from FIPS PUB 46-3. Bits are numbered **from 1, starting at the leftmost bit**. A permutation table lists, for each **output** position, which **input** bit goes there. For example the first entry of IP is `58`: *output bit 1 = input bit 58*.

---

## 7. The Key Schedule

The key schedule turns the one 64-bit key into sixteen 48-bit round keys.

### Step 1 — PC-1: drop the parity bits and split (64 → 56)

Every 8th bit of the key (bits 8, 16, …, 64) is a **parity bit** ([§23](#23-parity-bits-and-weak-keys)) and is thrown away. The other 56 are reordered:

| PC-1 | | | | | | |
|---|---|---|---|---|---|---|
| 57 | 49 | 41 | 33 | 25 | 17 | 9 |
| 1 | 58 | 50 | 42 | 34 | 26 | 18 |
| 10 | 2 | 59 | 51 | 43 | 35 | 27 |
| 19 | 11 | 3 | 60 | 52 | 44 | 36 |
| 63 | 55 | 47 | 39 | 31 | 23 | 15 |
| 7 | 62 | 54 | 46 | 38 | 30 | 22 |
| 14 | 6 | 61 | 53 | 45 | 37 | 29 |
| 21 | 13 | 5 | 28 | 20 | 12 | 4 |

The first 28 output bits are **C₀**, the last 28 are **D₀**.

### Step 2 — rotate C and D

Before each round, C and D are each rotated **left** — bits falling off the left re-enter on the right — by 1 or 2 positions:

| Round | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Shift | 1 | 1 | 2 | 2 | 2 | 2 | 2 | 2 | 1 | 2 | 2 | 2 | 2 | 2 | 2 | 1 |

The shifts add up to 28: after round 16, C and D are back where they started.

### Step 3 — PC-2: pick 48 bits (56 → 48)

From $C_i \parallel D_i$, PC-2 picks 48 of the 56 bits as round key $K_i$:

| PC-2 | | | | | |
|---|---|---|---|---|---|
| 14 | 17 | 11 | 24 | 1 | 5 |
| 3 | 28 | 15 | 6 | 21 | 10 |
| 23 | 19 | 12 | 4 | 26 | 8 |
| 16 | 7 | 27 | 20 | 13 | 2 |
| 41 | 52 | 31 | 37 | 47 | 55 |
| 30 | 40 | 51 | 45 | 33 | 48 |
| 44 | 49 | 39 | 56 | 34 | 53 |
| 46 | 42 | 50 | 36 | 29 | 32 |

Notice that the first 24 entries come only from C (1–28) and the last 24 only from D (29–56).

---

## 8. Initial and Final Permutation

The block is shuffled once at the start (IP) and shuffled back at the end (FP = IP⁻¹).

| IP | | | | | | | |
|---|---|---|---|---|---|---|---|
| 58 | 50 | 42 | 34 | 26 | 18 | 10 | 2 |
| 60 | 52 | 44 | 36 | 28 | 20 | 12 | 4 |
| 62 | 54 | 46 | 38 | 30 | 22 | 14 | 6 |
| 64 | 56 | 48 | 40 | 32 | 24 | 16 | 8 |
| 57 | 49 | 41 | 33 | 25 | 17 | 9 | 1 |
| 59 | 51 | 43 | 35 | 27 | 19 | 11 | 3 |
| 61 | 53 | 45 | 37 | 29 | 21 | 13 | 5 |
| 63 | 55 | 47 | 39 | 31 | 23 | 15 | 7 |

| FP | | | | | | | |
|---|---|---|---|---|---|---|---|
| 40 | 8 | 48 | 16 | 56 | 24 | 64 | 32 |
| 39 | 7 | 47 | 15 | 55 | 23 | 63 | 31 |
| 38 | 6 | 46 | 14 | 54 | 22 | 62 | 30 |
| 37 | 5 | 45 | 13 | 53 | 21 | 61 | 29 |
| 36 | 4 | 44 | 12 | 52 | 20 | 60 | 28 |
| 35 | 3 | 43 | 11 | 51 | 19 | 59 | 27 |
| 34 | 2 | 42 | 10 | 50 | 18 | 58 | 26 |
| 33 | 1 | 41 | 9 | 49 | 17 | 57 | 25 |

> [!NOTE]
> IP and FP add **no security**: they are public and undo each other. They made loading bytes into 1970s hardware easier. They must still be done exactly, or the result will not match other systems.

---

## 9. The Round Function f

$f(R, K)$ takes the 32-bit right half and a 48-bit round key and returns 32 bits, in four steps:

$$f(R, K) = P\big(S(E(R) \oplus K)\big)$$

### Step 1 — E: expand 32 → 48 bits

The 32 bits are written in 8 groups of 4, and each group borrows the neighbouring bit on each side (wrapping around), giving 8 groups of 6:

| E | | | | | |
|---|---|---|---|---|---|
| **32** | 1 | 2 | 3 | 4 | **5** |
| **4** | 5 | 6 | 7 | 8 | **9** |
| **8** | 9 | 10 | 11 | 12 | **13** |
| **12** | 13 | 14 | 15 | 16 | **17** |
| **16** | 17 | 18 | 19 | 20 | **21** |
| **20** | 21 | 22 | 23 | 24 | **25** |
| **24** | 25 | 26 | 27 | 28 | **29** |
| **28** | 29 | 30 | 31 | 32 | **1** |

The bold edge bits are the borrowed ones — this is how one bit gets to influence two S-boxes.

### Step 2 — XOR with the round key

$$E(R) \oplus K_i$$

48 bits XOR 48 bits *[[XOR §8](https://github.com/Mr-Alireza82/XOR#8-from-bits-to-bytes-bitwise-xor)]*. This is the **only** place the key enters the data.

### Step 3 — S-boxes: substitute 48 → 32 bits

The 48 bits are cut into eight 6-bit groups. Group 1 goes to box S1, group 2 to S2, and so on. Each box turns 6 bits into 4:

- The **outer** two bits (first and last) form the **row**: 0–3.
- The **inner** four bits form the **column**: 0–15.
- The number in that cell (0–15) is written as 4 bits.

```text
   6 input bits:   b1  b2 b3 b4 b5  b6
                   └────────┬────────┘
   row    = b1 b6       (2 bits → 0..3)
   column = b2 b3 b4 b5 (4 bits → 0..15)
```

Example: input `011000` → row `00` = 0, column `1100` = 12 → S1 row 0 column 12 = **5** = `0101`.

<details>
<summary>The eight S-boxes (click to open)</summary>

**S1**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 14 | 4 | 13 | 1 | 2 | 15 | 11 | 8 | 3 | 10 | 6 | 12 | 5 | 9 | 0 | 7 |
| **1** | 0 | 15 | 7 | 4 | 14 | 2 | 13 | 1 | 10 | 6 | 12 | 11 | 9 | 5 | 3 | 8 |
| **2** | 4 | 1 | 14 | 8 | 13 | 6 | 2 | 11 | 15 | 12 | 9 | 7 | 3 | 10 | 5 | 0 |
| **3** | 15 | 12 | 8 | 2 | 4 | 9 | 1 | 7 | 5 | 11 | 3 | 14 | 10 | 0 | 6 | 13 |

**S2**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 15 | 1 | 8 | 14 | 6 | 11 | 3 | 4 | 9 | 7 | 2 | 13 | 12 | 0 | 5 | 10 |
| **1** | 3 | 13 | 4 | 7 | 15 | 2 | 8 | 14 | 12 | 0 | 1 | 10 | 6 | 9 | 11 | 5 |
| **2** | 0 | 14 | 7 | 11 | 10 | 4 | 13 | 1 | 5 | 8 | 12 | 6 | 9 | 3 | 2 | 15 |
| **3** | 13 | 8 | 10 | 1 | 3 | 15 | 4 | 2 | 11 | 6 | 7 | 12 | 0 | 5 | 14 | 9 |

**S3**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 10 | 0 | 9 | 14 | 6 | 3 | 15 | 5 | 1 | 13 | 12 | 7 | 11 | 4 | 2 | 8 |
| **1** | 13 | 7 | 0 | 9 | 3 | 4 | 6 | 10 | 2 | 8 | 5 | 14 | 12 | 11 | 15 | 1 |
| **2** | 13 | 6 | 4 | 9 | 8 | 15 | 3 | 0 | 11 | 1 | 2 | 12 | 5 | 10 | 14 | 7 |
| **3** | 1 | 10 | 13 | 0 | 6 | 9 | 8 | 7 | 4 | 15 | 14 | 3 | 11 | 5 | 2 | 12 |

**S4**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 7 | 13 | 14 | 3 | 0 | 6 | 9 | 10 | 1 | 2 | 8 | 5 | 11 | 12 | 4 | 15 |
| **1** | 13 | 8 | 11 | 5 | 6 | 15 | 0 | 3 | 4 | 7 | 2 | 12 | 1 | 10 | 14 | 9 |
| **2** | 10 | 6 | 9 | 0 | 12 | 11 | 7 | 13 | 15 | 1 | 3 | 14 | 5 | 2 | 8 | 4 |
| **3** | 3 | 15 | 0 | 6 | 10 | 1 | 13 | 8 | 9 | 4 | 5 | 11 | 12 | 7 | 2 | 14 |

**S5**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 2 | 12 | 4 | 1 | 7 | 10 | 11 | 6 | 8 | 5 | 3 | 15 | 13 | 0 | 14 | 9 |
| **1** | 14 | 11 | 2 | 12 | 4 | 7 | 13 | 1 | 5 | 0 | 15 | 10 | 3 | 9 | 8 | 6 |
| **2** | 4 | 2 | 1 | 11 | 10 | 13 | 7 | 8 | 15 | 9 | 12 | 5 | 6 | 3 | 0 | 14 |
| **3** | 11 | 8 | 12 | 7 | 1 | 14 | 2 | 13 | 6 | 15 | 0 | 9 | 10 | 4 | 5 | 3 |

**S6**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 12 | 1 | 10 | 15 | 9 | 2 | 6 | 8 | 0 | 13 | 3 | 4 | 14 | 7 | 5 | 11 |
| **1** | 10 | 15 | 4 | 2 | 7 | 12 | 9 | 5 | 6 | 1 | 13 | 14 | 0 | 11 | 3 | 8 |
| **2** | 9 | 14 | 15 | 5 | 2 | 8 | 12 | 3 | 7 | 0 | 4 | 10 | 1 | 13 | 11 | 6 |
| **3** | 4 | 3 | 2 | 12 | 9 | 5 | 15 | 10 | 11 | 14 | 1 | 7 | 6 | 0 | 8 | 13 |

**S7**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 4 | 11 | 2 | 14 | 15 | 0 | 8 | 13 | 3 | 12 | 9 | 7 | 5 | 10 | 6 | 1 |
| **1** | 13 | 0 | 11 | 7 | 4 | 9 | 1 | 10 | 14 | 3 | 5 | 12 | 2 | 15 | 8 | 6 |
| **2** | 1 | 4 | 11 | 13 | 12 | 3 | 7 | 14 | 10 | 15 | 6 | 8 | 0 | 5 | 9 | 2 |
| **3** | 6 | 11 | 13 | 8 | 1 | 4 | 10 | 7 | 9 | 5 | 0 | 15 | 14 | 2 | 3 | 12 |

**S8**

| row \ col | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **0** | 13 | 2 | 8 | 4 | 6 | 15 | 11 | 1 | 10 | 9 | 3 | 14 | 5 | 0 | 12 | 7 |
| **1** | 1 | 15 | 13 | 8 | 10 | 3 | 7 | 4 | 12 | 5 | 6 | 11 | 0 | 14 | 9 | 2 |
| **2** | 7 | 11 | 4 | 1 | 9 | 12 | 14 | 2 | 0 | 6 | 10 | 13 | 15 | 3 | 5 | 8 |
| **3** | 2 | 1 | 14 | 7 | 4 | 10 | 8 | 13 | 15 | 12 | 9 | 0 | 3 | 5 | 6 | 11 |

</details>

Every row of every S-box contains each number 0–15 exactly once.

### Step 4 — P: shuffle the 32 bits

| P | | | |
|---|---|---|---|
| 16 | 7 | 20 | 21 |
| 29 | 12 | 28 | 17 |
| 1 | 15 | 23 | 26 |
| 5 | 18 | 31 | 10 |
| 2 | 8 | 24 | 14 |
| 32 | 27 | 3 | 9 |
| 19 | 13 | 30 | 6 |
| 22 | 11 | 4 | 25 |

P spreads the 4 output bits of each S-box over 4 different S-boxes of the next round — that is the diffusion.

---

## 10. Sixteen Rounds

Each round:

$$L_i = R_{i-1} \qquad\qquad R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$$

After round 16 the halves are swapped one last time and FP is applied:

$$C = FP(R_{16} \parallel L_{16})$$

The final swap makes encryption and decryption the exact same procedure ([§11](#11-decryption)).

---

## 11. Decryption

Decryption is **the same algorithm** with the round keys in reverse order: $K_{16}, K_{15}, \dots, K_1$.

<details>
<summary>Why does that work?</summary>

Take one round: $L_i = R_{i-1}$ and $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$.

Knowing $L_i$, $R_i$ and $K_i$, we can go back:

- $R_{i-1} = L_i$ — it was copied.
- $L_{i-1} = R_i \oplus f(R_{i-1}, K_i) = R_i \oplus f(L_i, K_i)$ — XOR with the same value undoes it *[[XOR §6](https://github.com/Mr-Alireza82/XOR#6-the-five-properties)]*.

That step is a round with the halves swapped and the same key. The final swap and IP/FP line the halves up so that running the whole machine with $K_{16} \dots K_1$ undoes the encryption exactly. $f$ is only ever run forwards.

</details>

---

# Part C — A Complete Worked Example

The classic example from J. Orlin Grabbe's *The DES Algorithm Illustrated*, computed and checked by the library in this repository:

| | Hex | Bits |
|---|---|---|
| Key $K$ | `133457799BBCDFF1` | `00010011 00110100 01010111 01111001 10011011 10111100 11011111 11110001` |
| Plaintext $P$ | `0123456789ABCDEF` | `00000001 00100011 01000101 01100111 10001001 10101011 11001101 11101111` |

## 12. The Round Keys

**PC-1** (64 → 56 bits):

| | Bits |
|---|---|
| $C_0 \parallel D_0$ | `1111000 0110011 0010101 0101111 0101010 1011001 1001111 0001111` (hex `F0CCAAF556678F`) |
| $C_0$ | `1111000011001100101010101111` |
| $D_0$ | `0101010101100110011110001111` |

**Round 1** shifts both halves left by 1:

| | Bits |
|---|---|
| $C_1$ | `1110000110011001010101011111` |
| $D_1$ | `1010101011001100111100011110` |

**PC-2** of $C_1 \parallel D_1$ gives $K_1$. All sixteen round keys:

| $i$ | $K_i$ (hex) | $K_i$ (bits, in 6-bit groups for the S-boxes) |
|---:|---|---|
| 1 | `1B02EFFC7072` | `000110 110000 001011 101111 111111 000111 000001 110010` |
| 2 | `79AED9DBC9E5` | `011110 011010 111011 011001 110110 111100 100111 100101` |
| 3 | `55FC8A42CF99` | `010101 011111 110010 001010 010000 101100 111110 011001` |
| 4 | `72ADD6DB351D` | `011100 101010 110111 010110 110110 110011 010100 011101` |
| 5 | `7CEC07EB53A8` | `011111 001110 110000 000111 111010 110101 001110 101000` |
| 6 | `63A53E507B2F` | `011000 111010 010100 111110 010100 000111 101100 101111` |
| 7 | `EC84B7F618BC` | `111011 001000 010010 110111 111101 100001 100010 111100` |
| 8 | `F78A3AC13BFB` | `111101 111000 101000 111010 110000 010011 101111 111011` |
| 9 | `E0DBEBEDE781` | `111000 001101 101111 101011 111011 011110 011110 000001` |
| 10 | `B1F347BA464F` | `101100 011111 001101 000111 101110 100100 011001 001111` |
| 11 | `215FD3DED386` | `001000 010101 111111 010011 110111 101101 001110 000110` |
| 12 | `7571F59467E9` | `011101 010111 000111 110101 100101 000110 011111 101001` |
| 13 | `97C5D1FABA41` | `100101 111100 010111 010001 111110 101011 101001 000001` |
| 14 | `5F43B7F2E73A` | `010111 110100 001110 110111 111100 101110 011100 111010` |
| 15 | `BF918D3D3F0A` | `101111 111001 000110 001101 001111 010011 111100 001010` |
| 16 | `CB3D8B0E17F5` | `110010 110011 110110 001011 000011 100001 011111 110101` |

---

## 13. Round 1 in Detail

**IP** of the plaintext, split into halves:

| | Hex | Bits |
|---|---|---|
| $IP(P)$ | `CC00CCFFF0AAF0AA` | `11001100 00000000 11001100 11111111 11110000 10101010 11110000 10101010` |
| $L_0$ | `CC00CCFF` | `1100 1100 0000 0000 1100 1100 1111 1111` |
| $R_0$ | `F0AAF0AA` | `1111 0000 1010 1010 1111 0000 1010 1010` |

**E, then XOR with $K_1$:**

| | Hex | Bits (6-bit groups) |
|---|---|---|
| $E(R_0)$ | `7A15557A1555` | `011110 100001 010101 010101 011110 100001 010101 010101` |
| $K_1$ | `1B02EFFC7072` | `000110 110000 001011 101111 111111 000111 000001 110010` |
| $E(R_0) \oplus K_1$ | `6117BA866527` | `011000 010001 011110 111010 100001 100110 010100 100111` |

**The eight S-boxes:**

| Box | 6-bit input | Row (b1 b6) | Column (b2–b5) | Value | 4-bit output |
|---|---|---|---|---:|---|
| S1 | `011000` | `00` = 0 | `1100` = 12 | 5 | `0101` |
| S2 | `010001` | `01` = 1 | `1000` = 8 | 12 | `1100` |
| S3 | `011110` | `00` = 0 | `1111` = 15 | 8 | `1000` |
| S4 | `111010` | `10` = 2 | `1101` = 13 | 2 | `0010` |
| S5 | `100001` | `11` = 3 | `0000` = 0 | 11 | `1011` |
| S6 | `100110` | `10` = 2 | `0011` = 3 | 5 | `0101` |
| S7 | `010100` | `00` = 0 | `1010` = 10 | 9 | `1001` |
| S8 | `100111` | `11` = 3 | `0011` = 3 | 7 | `0111` |

S-box output: `0101 1100 1000 0010 1011 0101 1001 0111` = `5C82B597`.

**P, then XOR into the left half:**

| | Hex | Bits |
|---|---|---|
| $f = P(S)$ | `234AA9BB` | `0010 0011 0100 1010 1010 1001 1011 1011` |
| $L_0$ | `CC00CCFF` | `1100 1100 0000 0000 1100 1100 1111 1111` |
| $R_1 = L_0 \oplus f$ | `EF4A6544` | `1110 1111 0100 1010 0110 0101 0100 0100` |
| $L_1 = R_0$ | `F0AAF0AA` | copied unchanged |

Check $R_1$ byte by byte with XOR's quick way *[[XOR §10](https://github.com/Mr-Alireza82/XOR#10-quick-way--nibble-by-nibble)]*: `CC ⊕ 23 = EF`, `00 ⊕ 4A = 4A`, `CC ⊕ A9 = 65`, `FF ⊕ BB = 44` ✓.

---

## 14. All Sixteen Rounds

| Round $i$ | $f(R_{i-1}, K_i)$ | $L_i$ | $R_i$ |
|---:|---|---|---|
| 0 | — | `CC00CCFF` | `F0AAF0AA` |
| 1 | `234AA9BB` | `F0AAF0AA` | `EF4A6544` |
| 2 | `3CAB87A3` | `EF4A6544` | `CC017709` |
| 3 | `4D166EB0` | `CC017709` | `A25C0BF4` |
| 4 | `BB23774C` | `A25C0BF4` | `77220045` |
| 5 | `2813ADC3` | `77220045` | `8A4FA637` |
| 6 | `9E45CD2C` | `8A4FA637` | `E967CD69` |
| 7 | `8C051C27` | `E967CD69` | `064ABA10` |
| 8 | `3C0E86F9` | `064ABA10` | `D5694B90` |
| 9 | `22367C6A` | `D5694B90` | `247CC67A` |
| 10 | `62BC9C22` | `247CC67A` | `B7D5D7B2` |
| 11 | `E104FA02` | `B7D5D7B2` | `C5783C78` |
| 12 | `C268CFEA` | `C5783C78` | `75BD1858` |
| 13 | `DDBB2922` | `75BD1858` | `18C3155A` |
| 14 | `B7318E55` | `18C3155A` | `C28C960D` |
| 15 | `5B81276E` | `C28C960D` | `43423234` |
| 16 | `C8C04F98` | `43423234` | `0A4CD995` |

Follow the diagonal: every $R_i$ reappears as $L_{i+1}$ in the next row. That is the Feistel copy.

---

## 15. The Result — and the Avalanche

| Step | Hex | Bits |
|---|---|---|
| $R_{16} \parallel L_{16}$ | `0A4CD99543423234` | `00001010 01001100 11011001 10010101 01000011 01000010 00110010 00110100` |
| $C = FP(R_{16} \parallel L_{16})$ | **`85E813540F0AB405`** | `10000101 11101000 00010011 01010100 00001111 00001010 10110100 00000101` |

$$\boxed{DES_{133457799BBCDFF1}(0123456789ABCDEF) = 85E813540F0AB405}$$

Now flip only the last plaintext bit:

| Plaintext | Ciphertext |
|---|---|
| `0123456789ABCDEF` | `85E813540F0AB405` |
| `0123456789ABCDEE` | `28378E295BE22A84` |
| Difference (XOR) | `ADDF9D7D54E89E81` → **37** of 64 bits differ |

---

# Part D — Triple DES

## 16. Why Not Double DES?

If 56 bits are too few, why not encrypt twice with two keys, $C = E_{K_2}(E_{K_1}(P))$, for 112 bits?

Because of the **meet-in-the-middle** attack. With one known plaintext/ciphertext pair, an attacker encrypts $P$ under all $2^{56}$ values of $K_1$ and stores the results, then decrypts $C$ under all $2^{56}$ values of $K_2$ and looks for a match in the middle. That costs about $2^{57}$ operations — barely more than single DES — plus a lot of memory. A third step is needed.

## 17. Triple DES — Encrypt, Decrypt, Encrypt

Triple DES (TDEA, 3DES, *DESede*) applies DES three times with up to three keys, in the order **E**ncrypt–**D**ecrypt–**E**ncrypt:

$$\boxed{C = E_{K_3}\big(D_{K_2}(E_{K_1}(P))\big) \qquad\qquad P = D_{K_1}\big(E_{K_2}(D_{K_3}(C))\big)}$$

Why decrypt in the middle? If all three keys are equal, the first two steps cancel and 3DES **becomes single DES**. One 3DES device can talk to an old DES device by loading the same key three times.

| Keying option | Key | Bytes | Hex digits | Security today | Where |
|---|---|---:|---:|---|---|
| 1 — three keys | $K_1 \parallel K_2 \parallel K_3$ | 24 | 48 | ~112 bits | Newer HSM keys |
| 2 — two keys ("double length") | $K_1 \parallel K_2$, $K_3 = K_1$ | 16 | 32 | ~80 bits | **Most payment keys**: TMK, TPK, TAK, ZMK, EMV card keys |
| 3 — one key | $K_1 = K_2 = K_3$ | 8 | 16 | broken (= DES) | Backward compatibility only |

### Example — encrypting the PIN block from the XOR article

The clear ISO 9564 format 0 PIN block `041225EEEEEEEEEE` *[[XOR §13](https://github.com/Mr-Alireza82/XOR#13-pin-block--iso-9564-format-0)]*, encrypted with the double-length demonstration key `0123456789ABCDEF FEDCBA9876543210`:

| Step | Operation | Key | Result |
|---|---|---|---|
| 0 | Clear PIN block | — | `041225EEEEEEEEEE` |
| 1 | DES **encrypt** | $K_1$ = `0123456789ABCDEF` | `C30C31411AA3D043` |
| 2 | DES **decrypt** | $K_2$ = `FEDCBA9876543210` | `D3264CDE6F005A09` |
| 3 | DES **encrypt** | $K_3 = K_1$ = `0123456789ABCDEF` | **`2A3D408A1977DDE9`** |

`2A3D408A1977DDE9` is what travels to the host in ISO 8583 field 52.

> [!TIP]
> **Do we need a separate "3DES" algorithm?** No. Triple DES is three calls to DES. Everything that is hard is in single DES; Triple DES is three lines on top of it — that is why both live in this one repository.

### Encrypting is E-D-E, decrypting is D-E-D

Both directions exist for Triple DES, exactly as for DES. **Decryption undoes the three steps in reverse order**, so each step turns into its opposite:

| | Step 1 | Step 2 | Step 3 |
|---|---|---|---|
| **Encrypt** (E-D-E) | encrypt with $K_1$ | decrypt with $K_2$ | encrypt with $K_3$ |
| **Decrypt** (D-E-D) | decrypt with $K_3$ | encrypt with $K_2$ | decrypt with $K_1$ |

The "decrypt with $K_2$" in the middle of encryption does not undo anything, because $K_2$ is a different key: it is just one more scramble. It is a decryption only by name — chosen so that $K_1 = K_2 = K_3$ collapses into single DES.

---

# Part E — Longer Messages: Padding, Modes and the IV

DES encrypts exactly **one 8-byte block**. Real data is longer, and rarely a multiple of 8. Three choices, made *outside* DES, turn the block machine into a message machine:

| Choice | Question it answers | Options in this library |
|---|---|---|
| **Algorithm** | Which block machine? | `DES`, `TRIPLE_DES` |
| **Padding** | How is the last block filled up? | `NONE`, `ISO_9797_1_METHOD_1`, `ISO_9797_1_METHOD_2`, `PKCS7` |
| **Mode** | How are the blocks connected? | `ECB`, `CBC` |
| **IV** | Where does the chain start? | 8 bytes — CBC only |

All three are the same for every block cipher: AES uses the same padding methods and modes with 16-byte blocks.

## 18. Padding

Take the message `PAYMENT123` — 10 bytes: `50 41 59 4D 45 4E 54 31 32 33`. That is one full block and 2 bytes left over. Padding fills the last block:

| Padding | Rule | Last block of `PAYMENT123` | Removable? |
|---|---|---|---|
| None | Data must already be whole blocks | ✗ error: 10 is not a multiple of 8 | — |
| ISO/IEC 9797-1 method 1 | Add `00` until whole; add nothing if already whole | `32 33 00 00 00 00 00 00` | ✗ the data could itself end in `00` |
| ISO/IEC 9797-1 method 2 | **Always** add one `80`, then `00` until whole | `32 33 80 00 00 00 00 00` | ✓ cut after the last `80` |
| PKCS #7 | Add N bytes of value N (1–8) | `32 33 06 06 06 06 06 06` | ✓ the last byte says how many to cut |

When the data is already whole blocks, method 2 and PKCS #7 add a **full extra block** (`80 00 … 00` or `08 08 … 08`), so that the receiver always finds padding to remove. Method 1 adds nothing.

> [!NOTE]
> "Zero padding" *is* ISO 9797-1 method 1. The [Retail MAC](https://github.com/Mr-Alireza82/ANSI-X9.19-Retail-MAC-Algorithm) and most ISO 8583 MACs use it; it is fine there because the MAC is only compared, never "decrypted back". For encrypting data you want back, use method 2 or PKCS #7. The padding method is part of the agreement between the two systems — both sides must use the same one.

## 19. ECB — Every Block Alone

**Electronic Codebook**: cut the padded data into blocks and encrypt each one on its own.

$$C_i = E_K(P_i) \qquad\qquad P_i = D_K(C_i)$$

```text
   P1          P2          P3
   │           │           │
 E(K)        E(K)        E(K)
   │           │           │
   C1          C2          C3
```

No IV. Simple, and blocks can be processed in any order. But **equal input blocks give equal output blocks**. Two customers with the same PIN block:

| | Block 1 | Block 2 |
|---|---|---|
| Plain | `041225EEEEEEEEEE` | `041225EEEEEEEEEE` |
| ECB, TDES key `0123456789ABCDEF FEDCBA9876543210` | `2A3D408A1977DDE9` | `2A3D408A1977DDE9` ← same, visible |

An attacker sees that the two blocks are equal without breaking anything. That is why ECB is used only for **single blocks that already look random**: one PIN block, one key under a key-encryption key. Never for longer messages.

## 20. CBC — Blocks in a Chain

**Cipher Block Chaining**: before a block is encrypted, it is XORed *[[XOR](https://github.com/Mr-Alireza82/XOR)]* with the previous **encrypted** block. The first block has no previous block, so it is XORed with an 8-byte **initialization vector (IV)**.

$$C_0 = IV \qquad C_i = E_K(P_i \oplus C_{i-1}) \qquad\qquad P_i = D_K(C_i) \oplus C_{i-1}$$

```text
          P1               P2               P3
          │                │                │
 IV ──►  XOR     ┌──────► XOR     ┌──────► XOR
          │      │         │      │         │
        E(K)     │       E(K)     │       E(K)
          │      │         │      │         │
          C1 ────┘         C2 ────┘         C3
```

Every encrypted block now depends on **all** blocks before it. The same two PIN blocks, CBC with IV `0000000000000000`:

| | Block 1 | Block 2 |
|---|---|---|
| Plain $P_i$ | `041225EEEEEEEEEE` | `041225EEEEEEEEEE` |
| $P_i \oplus C_{i-1}$ | `041225EEEEEEEEEE` (⊕ IV = 0) | `2E2F6564F7993307` (⊕ $C_1$) |
| CBC $C_i$ | `2A3D408A1977DDE9` | `12652D81BCB04D03` ← different |

### CBC is the Retail MAC's engine

`PAYMENT123` with method 1 padding, CBC, single DES key $K_1$ = `0123456789ABCDEF`, IV = zeros:

| $i$ | $P_i$ | $P_i \oplus C_{i-1}$ | $C_i = E_{K_1}(\dots)$ |
|---|---|---|---|
| 1 | `5041594D454E5431` | `5041594D454E5431` | `355227E11D967D54` |
| 2 | `3233000000000000` | `076127E11D967D54` | `775332C133888CD3` |

These are exactly $H_1$ and $H_2$ of the [Retail MAC article](https://github.com/Mr-Alireza82/ANSI-X9.19-Retail-MAC-Algorithm): its chaining phase **is** DES-CBC. The MAC only adds the final "decrypt with $K_2$, encrypt with $K_1$" on the last block.

### Rules for the IV

| Rule | Why |
|---|---|
| Exactly 8 bytes (one block) | It stands in for "the previous block" |
| Both sides use the same IV | Decryption needs the same chain start |
| Not secret | It may travel with the message |
| Unpredictable for encryption of data | A fixed IV makes equal first blocks visible again |
| All zeros for MACs | Fixed by the MAC standards (ISO 9797-1, X9.19) |
| Never given for ECB | ECB has no chain; the library rejects it |

### In code

```java
DesCipher cipher = DesCipher.of(DesAlgorithm.TRIPLE_DES, BlockMode.CBC, Padding.ISO_9797_1_METHOD_2);
byte[] encrypted = cipher.encrypt(key, iv, data);     // CBC: key, IV, data
byte[] plain     = cipher.decrypt(key, iv, encrypted);

DesCipher pinBlocks = DesCipher.of(DesAlgorithm.TRIPLE_DES, BlockMode.ECB, Padding.NONE);
byte[] field52 = pinBlocks.encrypt(tpk, clearPinBlock);  // ECB: no IV
```

---

# Part F — DES in Payment Systems

## 21. Where DES Still Runs

| Use | Algorithm | What is encrypted |
|---|---|---|
| PIN encryption | TDES (TPK, PIN key) | The 8-byte PIN block, field 52 |
| Key exchange | TDES (TMK / ZMK, key-encryption key) | Other keys, "key under key" |
| Retail MAC (ANSI X9.19) | DES for each block, TDES finish | The MAC over a message *[[Retail MAC](https://github.com/Mr-Alireza82/ANSI-X9.19-Retail-MAC-Algorithm)]* |
| DUKPT (ANSI X9.24, TDES variant) | TDES | A unique key per transaction |
| EMV cryptograms (ARQC / ARPC) | TDES | Card-generated transaction proof |
| Key check value | DES / TDES | Eight zero bytes ([§22](#22-key-check-value)) |

The [Retail MAC](https://github.com/Mr-Alireza82/ANSI-X9.19-Retail-MAC-Algorithm) example can be checked with this library: $E_{K_1}(5041594D454E5431)$ = `355227E11D967D54`, $E_{K_1}(076127E11D967D54)$ = `775332C133888CD3`, $D_{K_2}(775332C133888CD3)$ = `5686442BF278651D`, $E_{K_1}(5686442BF278651D)$ = `89FA1AAA2C6E27ED` — all part of the tests.

## 22. Key Check Value

How do two people confirm they loaded **the same** key without showing it? They both encrypt eight zero bytes with it and compare the first 3 bytes (6 hex digits). This is the **key check value (KCV)**.

| Key | Algorithm | $E_K(0000000000000000)$ | KCV |
|---|---|---|---|
| `0123456789ABCDEF` | DES | `D5D44FF720683D0D` | **`D5D44F`** |
| `133457799BBCDFF1` | DES | `948A43F98A834F7E` | **`948A43`** |
| `0123456789ABCDEF FEDCBA9876543210` | TDES | `08D7B4FB629D0885` | **`08D7B4`** |

Key custodians read the KCV aloud after entering their key components *[[XOR §12](https://github.com/Mr-Alireza82/XOR#12-key-components)]*: if the KCV matches the one printed on the key form, the key is right. Three bytes reveal practically nothing about the key.

## 23. Parity Bits and Weak Keys

### Parity

The lowest bit of every key byte (bits 8, 16, …, 64) is not used by DES ([PC-1](#7-the-key-schedule) skips it). By convention it is set so that each byte has an **odd** number of 1 bits, which catches typing errors in key entry.

| Byte | Bits | Number of 1s | Odd parity? |
|---|---|---:|---|
| `01` | `0000 0001` | 1 | ✓ |
| `23` | `0010 0011` | 3 | ✓ |
| `22` | `0010 0010` | 2 | ✗ → fix to `23` |

`0123456789ABCDEF` and `0022446688AACCEE` differ only in parity bits, so they are **the same DES key** and encrypt identically. Many HSMs reject keys with wrong parity; Java ignores parity.

### Weak keys

For four keys, all sixteen round keys are identical, so encrypting twice gives back the plaintext:

| Weak key (with parity) |
|---|
| `0101010101010101` |
| `FEFEFEFEFEFEFEFE` |
| `E0E0E0E0F1F1F1F1` |
| `1F1F1F1F0E0E0E0E` |

There are also 12 semi-weak keys (pairs that undo each other). Proper random key generation avoids them; HSMs check for them.

---

# Part G — In Code

## 24. Two Ways: Standard and Paper

| | Standard way — `DesCipher`, `Des` | Paper way — `SimpleDesCipher`, `SimpleDes` |
|---|---|---|
| How | Java's own `javax.crypto.Cipher` (`DES` and `DESede`, ECB and CBC); padding by this library | Every table of this article, bit by bit; CBC chaining written out with `Xor` |
| Speed | Fast, optimised | Slow |
| Timing safety | Platform implementation | Not hardened — learning only |
| Uses | Real code | Learning, checking by hand, a second opinion in tests |
| Shows steps | No | `encryptWithSteps(...)` returns every value of Part C |

The paper way is built from the two earlier libraries, using **their standard (quick) ways**: every mix is `Xor.xor` from [XOR](https://github.com/Mr-Alireza82/XOR), and every hex ↔ bytes step is `ByteEncoding` from [Base Conversion](https://github.com/Mr-Alireza82/Base-Conversion).

**How it is tested:** both ways are compared on known answers (this article's example, the FIPS 81 ECB and CBC vectors, the Retail MAC chaining values, the KCV), on random keys and data for every combination of algorithm, mode and padding, and in both directions. The steps of the paper way are checked against Part C.

**Run it yourself:** the code is in [`src/main/java`](src/main/java/io/github/mralireza82/des) and the tests in [`src/test/java`](src/test/java/io/github/mralireza82/des). With Java 17 or newer installed:

```bash
./gradlew test        # Windows: gradlew.bat test
```

**Use it in your project** (Gradle, through [JitPack](https://jitpack.io/#Mr-Alireza82/DES)):

```kotlin
repositories {
    mavenCentral()
    maven("https://jitpack.io")
}

dependencies {
    implementation("com.github.Mr-Alireza82:DES:v1.1.0")
}
```

## 25. Using the Library

Package `io.github.mralireza82.des`, pure Java 17. It depends on [XOR](https://github.com/Mr-Alireza82/XOR), which brings [Base Conversion](https://github.com/Mr-Alireza82/Base-Conversion).

| Class | Use it for |
|---|---|
| `DesCipher` | **Messages**, the standard way: `DesCipher.of(algorithm, mode, padding)`, then `encrypt` / `decrypt` |
| `SimpleDesCipher` | **Messages**, the paper way: the same API |
| `DesAlgorithm` / `BlockMode` / `Padding` | The options: `DES`, `TRIPLE_DES` / `ECB`, `CBC` / `NONE`, `ISO_9797_1_METHOD_1`, `ISO_9797_1_METHOD_2`, `PKCS7` |
| `Des` | **One block**, the standard way: `encrypt`, `decrypt`, `encryptTriple`, `decryptTriple` |
| `SimpleDes` | **One block**, the paper way: the same four, plus `roundKeys` and `encryptWithSteps` |
| `DesKeys` | `checkValue` (KCV), `hasOddParity`, `withOddParity` |
| `DesSteps` | Every intermediate value of one block encryption, in hex |

```java
byte[] key   = ByteEncoding.fromHex("133457799BBCDFF1");
byte[] block = ByteEncoding.fromHex("0123456789ABCDEF");

// Messages: choose algorithm, mode and padding once, then encrypt / decrypt
DesCipher cbc = DesCipher.of(DesAlgorithm.DES, BlockMode.CBC, Padding.ISO_9797_1_METHOD_1);
byte[] message = "PAYMENT123".getBytes(StandardCharsets.US_ASCII);
ByteEncoding.toHex(cbc.encrypt(ByteEncoding.fromHex("0123456789ABCDEF"), new byte[8], message));
                                                                    // "355227E11D967D54775332C133888CD3"
SimpleDesCipher.of(DesAlgorithm.DES, BlockMode.CBC, Padding.ISO_9797_1_METHOD_1);  // same API, paper way

// One block, standard way
ByteEncoding.toHex(Des.encrypt(key, block));                        // "85E813540F0AB405"
byte[] tpk = ByteEncoding.fromHex("0123456789ABCDEFFEDCBA9876543210");
ByteEncoding.toHex(Des.encryptTriple(tpk, ByteEncoding.fromHex("041225EEEEEEEEEE")));  // "2A3D408A1977DDE9"
ByteEncoding.toHex(DesKeys.checkValue(tpk));                        // "08D7B4"

// Paper way: same results, every step visible
DesSteps steps = SimpleDes.encryptWithSteps(key, block);
steps.roundKeys().get(0);                                           // "1B02EFFC7072"
steps.rounds().get(0).right();                                      // "EF4A6544"
steps.output();                                                     // "85E813540F0AB405"
```

**Rules:**

- A DES key is 8 bytes; a Triple DES key 16 or 24 bytes; a block and an IV 8 bytes. Anything else throws `IllegalArgumentException`.
- ECB: `encrypt(key, data)`, no IV. CBC: `encrypt(key, iv, data)`, IV required. Mixing them up throws.
- With padding `NONE` the data must be whole blocks. Method 1 padding cannot be removed: decryption returns the padded data.
- Wrong padding after decryption (usually a wrong key or IV) throws `IllegalArgumentException`.
- Inputs are never changed; ciphers are immutable and thread-safe.

> [!CAUTION]
> Real payment keys never appear in application memory as plain bytes: they live inside an HSM or the terminal's secure PIN pad, and the application only asks those devices to use them. Use this library for learning, tests, simulators and tools — not to hold production keys.

---

# Part H — Reference

## 26. Cheat Sheet

| Item | Value |
|---|---|
| Block | 64 bits |
| Key | 64 bits stored, 56 used (8 parity bits) |
| Round keys | 16 × 48 bits (PC-1, rotate 1 or 2, PC-2) |
| Round | $L_i = R_{i-1}$, $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$ |
| Round function | $f(R, K) = P(S(E(R) \oplus K))$ |
| E / S / P | 32 → 48 / 48 → 32 / 32 → 32 bits |
| S-box reading | row = outer 2 bits, column = inner 4 bits |
| Output | $FP(R_{16} \parallel L_{16})$ |
| Decryption | Same, round keys $K_{16} \dots K_1$ |
| Triple DES | $E_{K_3}(D_{K_2}(E_{K_1}(P)))$; 16-byte key → $K_3 = K_1$ |
| Triple DES decryption | $D_{K_1}(E_{K_2}(D_{K_3}(C)))$ — D-E-D |
| KCV | First 3 bytes of $E_K(00 \dots 00)$ |
| ECB | $C_i = E_K(P_i)$ — no IV; single blocks only |
| CBC | $C_i = E_K(P_i \oplus C_{i-1})$, $C_0 = IV$ (8 bytes) |
| Padding | ISO 9797-1 M1: `00 …`; M2: `80 00 …`; PKCS #7: N bytes of N |
| Example | $DES_{133457799BBCDFF1}(0123456789ABCDEF) = 85E813540F0AB405$ |

## 27. Practice

1. How many of the 64 bits of a DES key change the result?
2. Look up S1 for the input `011011`.
3. During decryption, which round key is used in round 1?
4. What does Triple DES with the 16-byte key `0123456789ABCDEF0123456789ABCDEF` equal?
5. Are `0123456789ABCDEF` and `0022446688AACCEE` different DES keys?
6. Why is double DES not used?
7. Why does $f$ not need to be reversible?

<details>
<summary>Answers</summary>

1. **56.** The 8 parity bits are dropped by PC-1.
2. Row `01` = 1, column `1101` = 13 → S1[1][13] = **5** = `0101`.
3. **$K_{16}$** — decryption uses the round keys in reverse.
4. **Single DES** with key `0123456789ABCDEF`: $E_{K_1}(D_{K_1}(E_{K_1}(P))) = E_{K_1}(P)$.
5. **No.** They differ only in parity bits, which DES ignores.
6. Meet-in-the-middle breaks it with about $2^{57}$ work — little better than single DES.
7. Because the Feistel structure only ever computes $f$ forwards and removes it with XOR ([§4](#4-the-feistel-idea--decryption-for-free)).

</details>

---

## 28. Conclusion

- DES is a **symmetric block cipher**: 8-byte block, 8-byte key with 56 effective bits, 16 rounds.
- Each round is a **Feistel** step: $L_i = R_{i-1}$, $R_i = L_{i-1} \oplus f(R_{i-1}, K_i)$ — decryption is the same with reversed keys, thanks to XOR.
- The round function **expands, mixes in the key with XOR, substitutes through S-boxes, and shuffles**.
- **Triple DES** is DES three times, encrypt–decrypt–encrypt; the double-length form ($K_1 K_2 K_1$) carries most of today's payment keys.
- Single DES is broken and Triple DES is deprecated, but both are still everywhere in payments: PIN blocks, key exchange, KCVs, the Retail MAC.

With Base Conversion, XOR and DES in hand, every building block of the [ANSI X9.19 Retail MAC](https://github.com/Mr-Alireza82/ANSI-X9.19-Retail-MAC-Algorithm) is now explained.

---

## References and Further Reading

- [FIPS PUB 46-3 — Data Encryption Standard (DES)](https://csrc.nist.gov/pubs/fips/46-3/final) (withdrawn 2005; the tables)
- [NIST SP 800-67 Rev. 2 — Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher](https://csrc.nist.gov/pubs/sp/800/67/r2/final)
- [NIST SP 800-131A Rev. 2 — Transitioning the Use of Cryptographic Algorithms and Key Lengths](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- ANSI X9.52 — Triple Data Encryption Algorithm Modes of Operation
- ANSI X9.24-1 — Retail Financial Services Symmetric Key Management (key components, KCV)
- J. Orlin Grabbe — *The DES Algorithm Illustrated* (the worked example of Part C)
- C. E. Shannon — *Communication Theory of Secrecy Systems*, 1949 (confusion and diffusion)
- [Java SE 17 — `javax.crypto.Cipher`](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Cipher.html)

**Related articles:**

- [Base Conversion — Bits, Bytes and the Four Number Bases](https://github.com/Mr-Alireza82/Base-Conversion)
- [XOR — Exclusive OR](https://github.com/Mr-Alireza82/XOR)
- [ANSI X9.19 — Retail MAC Algorithm](https://github.com/Mr-Alireza82/ANSI-X9.19-Retail-MAC-Algorithm)

---

## License

[MIT](LICENSE) — free to use, copy, modify and share, including commercially. Keep the copyright notice.
