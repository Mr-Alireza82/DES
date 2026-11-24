package io.github.mralireza82.des;

import java.util.Arrays;
import java.util.Objects;

/**
 * Key rules shared by both ways: key lengths, the parity bit of every key byte, splitting a Triple DES key
 * into its single DES keys, and the key check value (KCV) used to confirm a key without revealing it.
 */
public final class DesKeys {
    /** A single DES key and a DES block are both 8 bytes (64 bits). */
    public static final int BLOCK_SIZE = 8;

    private DesKeys() {
    }

    /**
     * True if every byte has an odd number of 1 bits. DES uses only 7 bits of each key byte; the lowest
     * bit is a parity bit that only detects typing or transmission errors.
     */
    public static boolean hasOddParity(byte[] key) {
        Objects.requireNonNull(key, "key");
        for (byte b : key) {
            if (Integer.bitCount(b & 0xFF) % 2 == 0) {
                return false;
            }
        }
        return true;
    }

    /** A copy of the key with the lowest bit of each byte set so that every byte has odd parity. */
    public static byte[] withOddParity(byte[] key) {
        Objects.requireNonNull(key, "key");
        byte[] fixed = key.clone();
        for (int i = 0; i < fixed.length; i++) {
            int sevenBits = fixed[i] & 0xFE;
            fixed[i] = (byte) (Integer.bitCount(sevenBits) % 2 == 0 ? sevenBits | 1 : sevenBits);
        }
        return fixed;
    }

    /**
     * Key check value: encrypt eight zero bytes with the key and keep the first 3 bytes. Two people can
     * compare KCVs to confirm they hold the same key without showing it. 8-byte keys use DES, 16- and 24-byte
     * keys Triple DES.
     */
    public static byte[] checkValue(byte[] key) {
        byte[] zeros = new byte[BLOCK_SIZE];
        byte[] encrypted = Objects.requireNonNull(key, "key").length == BLOCK_SIZE
                ? Des.encrypt(key, zeros)
                : Des.encryptTriple(key, zeros);
        return Arrays.copyOf(encrypted, 3);
    }

    static void requireSingleKey(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("a DES key is 8 bytes, got " + key.length);
        }
    }

    static void requireBlock(byte[] block) {
        Objects.requireNonNull(block, "block");
        if (block.length != BLOCK_SIZE) {
            throw new IllegalArgumentException(
                    "DES works on blocks of exactly 8 bytes, got " + block.length + " (pad the data first)");
        }
    }

    /** The 24-byte form K1 K2 K3 that Java's DESede wants; a 16-byte key K1 K2 becomes K1 K2 K1. */
    static byte[] threeKeyForm(byte[] key) {
        byte[][] parts = tripleParts(key);
        byte[] full = new byte[24];
        for (int i = 0; i < 3; i++) {
            System.arraycopy(parts[i], 0, full, 8 * i, 8);
        }
        return full;
    }

    /** K1, K2, K3 of a Triple DES key. A 16-byte (double-length) key reuses K1 as K3. */
    static byte[][] tripleParts(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != 16 && key.length != 24) {
            throw new IllegalArgumentException("a Triple DES key is 16 or 24 bytes, got " + key.length);
        }
        byte[] k1 = Arrays.copyOfRange(key, 0, 8);
        byte[] k2 = Arrays.copyOfRange(key, 8, 16);
        byte[] k3 = key.length == 24 ? Arrays.copyOfRange(key, 16, 24) : k1.clone();
        return new byte[][] {k1, k2, k3};
    }
}
