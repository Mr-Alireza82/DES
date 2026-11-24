package io.github.mralireza82.des;

import java.util.Objects;

/** The input rules both {@link DesCipher} and {@link SimpleDesCipher} enforce, so both reject the same mistakes. */
final class CipherChecks {
    private CipherChecks() {
    }

    static void requireSettings(DesAlgorithm algorithm, BlockMode mode, Padding padding) {
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(padding, "padding");
    }

    /** Key length fits the algorithm; an IV is given exactly when the mode needs one, and is 8 bytes. */
    static void requireInputs(DesAlgorithm algorithm, BlockMode mode, byte[] key, byte[] iv, byte[] data) {
        algorithm.requireKey(key);
        Objects.requireNonNull(data, "data");
        if (mode.needsIv() && iv == null) {
            throw new IllegalArgumentException(mode + " needs an 8-byte IV: use encrypt/decrypt(key, iv, data)");
        }
        if (!mode.needsIv() && iv != null) {
            throw new IllegalArgumentException(mode + " does not use an IV: use encrypt/decrypt(key, data)");
        }
        if (iv != null && iv.length != DesKeys.BLOCK_SIZE) {
            throw new IllegalArgumentException("the IV is 8 bytes, got " + iv.length);
        }
    }

    static void requireWholeBlocks(byte[] data) {
        if (data.length % DesKeys.BLOCK_SIZE != 0) {
            throw new IllegalArgumentException(
                    "encrypted data is always a multiple of 8 bytes, got " + data.length);
        }
    }
}
