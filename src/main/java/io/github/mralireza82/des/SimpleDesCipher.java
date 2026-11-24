package io.github.mralireza82.des;

import io.github.mralireza82.xor.Xor;

import java.util.Arrays;

/**
 * The same as {@link DesCipher}, the paper way: every block goes through {@link SimpleDes} and the CBC
 * chaining is written out with {@link Xor}, block by block. Slow and not hardened; for learning and as a
 * second opinion in tests. Both give identical results.
 */
public final class SimpleDesCipher {
    private static final int BLOCK = DesKeys.BLOCK_SIZE;

    private final DesAlgorithm algorithm;
    private final BlockMode mode;
    private final Padding padding;

    private SimpleDesCipher(DesAlgorithm algorithm, BlockMode mode, Padding padding) {
        CipherChecks.requireSettings(algorithm, mode, padding);
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
    }

    public static SimpleDesCipher of(DesAlgorithm algorithm, BlockMode mode, Padding padding) {
        return new SimpleDesCipher(algorithm, mode, padding);
    }

    /** ECB: pads, then encrypts every block on its own. */
    public byte[] encrypt(byte[] key, byte[] data) {
        return encrypt(key, null, data);
    }

    /** ECB: decrypts every block on its own, then removes the padding. */
    public byte[] decrypt(byte[] key, byte[] data) {
        return decrypt(key, null, data);
    }

    /**
     * CBC encryption: {@code C1 = E(P1 XOR IV)}, {@code C2 = E(P2 XOR C1)}, ... (ECB: {@code Ci = E(Pi)}).
     */
    public byte[] encrypt(byte[] key, byte[] iv, byte[] data) {
        CipherChecks.requireInputs(algorithm, mode, key, iv, data);
        byte[] plain = padding.pad(data);
        byte[] result = new byte[plain.length];
        byte[] previous = iv;
        for (int at = 0; at < plain.length; at += BLOCK) {
            byte[] block = Arrays.copyOfRange(plain, at, at + BLOCK);
            if (mode == BlockMode.CBC) {
                block = Xor.xor(block, previous);
            }
            byte[] encrypted = encryptBlock(key, block);
            System.arraycopy(encrypted, 0, result, at, BLOCK);
            previous = encrypted;
        }
        return result;
    }

    /**
     * CBC decryption: {@code P1 = D(C1) XOR IV}, {@code P2 = D(C2) XOR C1}, ... (ECB: {@code Pi = D(Ci)}).
     */
    public byte[] decrypt(byte[] key, byte[] iv, byte[] data) {
        CipherChecks.requireInputs(algorithm, mode, key, iv, data);
        CipherChecks.requireWholeBlocks(data);
        byte[] result = new byte[data.length];
        byte[] previous = iv;
        for (int at = 0; at < data.length; at += BLOCK) {
            byte[] encrypted = Arrays.copyOfRange(data, at, at + BLOCK);
            byte[] block = decryptBlock(key, encrypted);
            if (mode == BlockMode.CBC) {
                block = Xor.xor(block, previous);
            }
            System.arraycopy(block, 0, result, at, BLOCK);
            previous = encrypted;
        }
        return padding.unpad(result);
    }

    private byte[] encryptBlock(byte[] key, byte[] block) {
        return algorithm == DesAlgorithm.DES ? SimpleDes.encrypt(key, block) : SimpleDes.encryptTriple(key, block);
    }

    private byte[] decryptBlock(byte[] key, byte[] block) {
        return algorithm == DesAlgorithm.DES ? SimpleDes.decrypt(key, block) : SimpleDes.decryptTriple(key, block);
    }
}
