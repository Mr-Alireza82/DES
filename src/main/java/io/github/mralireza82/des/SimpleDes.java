package io.github.mralireza82.des;

import io.github.mralireza82.baseconversion.ByteEncoding;
import io.github.mralireza82.xor.Xor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * DES and Triple DES the paper way: every bit is moved by the FIPS 46-3 tables, every mix is a XOR
 * ({@link Xor}), every substitution is a look-up in an S-box. Far slower than {@link Des} and not hardened
 * against timing attacks, so it is for learning and as a second opinion in tests only. Both give
 * identical results. {@link #encryptWithSteps(byte[], byte[])} shows every intermediate value.
 */
public final class SimpleDes {
    private static final int ROUNDS = 16;

    private SimpleDes() {
    }

    /** Encrypts one 8-byte block with an 8-byte key. */
    public static byte[] encrypt(byte[] key, byte[] block) {
        return crypt(key, block, false, null);
    }

    /** Decrypts one 8-byte block: the same steps with the round keys in reverse order. */
    public static byte[] decrypt(byte[] key, byte[] block) {
        return crypt(key, block, true, null);
    }

    /** Encrypts one block and records every step: round keys, both halves after each round, and more. */
    public static DesSteps encryptWithSteps(byte[] key, byte[] block) {
        List<DesSteps.Round> rounds = new ArrayList<>();
        String[] summary = new String[3];
        byte[] output = crypt(key, block, false, new Recorder(rounds, summary));
        List<String> roundKeys = new ArrayList<>();
        for (byte[] roundKey : roundKeys(key)) {
            roundKeys.add(ByteEncoding.toHex(roundKey));
        }
        return new DesSteps(ByteEncoding.toHex(key), summary[0], List.copyOf(roundKeys), ByteEncoding.toHex(block),
                summary[1], List.copyOf(rounds), summary[2], ByteEncoding.toHex(output));
    }

    /** Triple DES encryption: E(K3, D(K2, E(K1, block))). A 16-byte key reuses K1 as K3. */
    public static byte[] encryptTriple(byte[] key, byte[] block) {
        byte[][] k = DesKeys.tripleParts(key);
        return encrypt(k[2], decrypt(k[1], encrypt(k[0], block)));
    }

    /** Triple DES decryption: D(K1, E(K2, D(K3, block))), the encryption steps undone in reverse order. */
    public static byte[] decryptTriple(byte[] key, byte[] block) {
        byte[][] k = DesKeys.tripleParts(key);
        return decrypt(k[0], encrypt(k[1], decrypt(k[2], block)));
    }

    /**
     * The 16 round keys of 48 bits. PC-1 picks 56 of the 64 key bits (C = first 28, D = last 28); before each
     * round C and D rotate left by 1 or 2; PC-2 picks 48 of the 56 bits as the round key.
     */
    public static List<byte[]> roundKeys(byte[] key) {
        DesKeys.requireSingleKey(key);
        byte[] cd = permute(key, DesTables.PC1);
        List<byte[]> keys = new ArrayList<>(ROUNDS);
        for (int round = 0; round < ROUNDS; round++) {
            cd = rotateHalvesLeft(cd, DesTables.SHIFTS[round]);
            keys.add(permute(cd, DesTables.PC2));
        }
        return keys;
    }

    private static byte[] crypt(byte[] key, byte[] block, boolean decrypt, Recorder recorder) {
        DesKeys.requireBlock(block);
        List<byte[]> keys = roundKeys(key);

        byte[] afterIp = permute(block, DesTables.IP);
        byte[] left = Arrays.copyOfRange(afterIp, 0, 4);
        byte[] right = Arrays.copyOfRange(afterIp, 4, 8);

        for (int round = 0; round < ROUNDS; round++) {
            byte[] roundKey = keys.get(decrypt ? ROUNDS - 1 - round : round);

            byte[] expanded = permute(right, DesTables.E);
            byte[] mixed = Xor.xor(expanded, roundKey);
            byte[] substituted = substitute(mixed);
            byte[] f = permute(substituted, DesTables.P);

            byte[] newRight = Xor.xor(left, f);
            left = right;
            right = newRight;

            if (recorder != null) {
                recorder.rounds.add(new DesSteps.Round(round + 1, ByteEncoding.toHex(expanded),
                        ByteEncoding.toHex(mixed), ByteEncoding.toHex(substituted), ByteEncoding.toHex(f),
                        ByteEncoding.toHex(left), ByteEncoding.toHex(right)));
            }
        }

        byte[] beforeFp = concat(right, left);
        if (recorder != null) {
            recorder.summary[0] = ByteEncoding.toHex(permute(key, DesTables.PC1));
            recorder.summary[1] = ByteEncoding.toHex(afterIp);
            recorder.summary[2] = ByteEncoding.toHex(beforeFp);
        }
        return permute(beforeFp, DesTables.FP);
    }

    /**
     * The eight S-boxes: the 48 bits are cut into eight groups of 6. In each group the outer two bits choose
     * the row (0-3) and the inner four bits the column (0-15); the box gives 4 bits back. 48 bits become 32.
     */
    static byte[] substitute(byte[] bits48) {
        byte[] out = new byte[4];
        for (int box = 0; box < 8; box++) {
            int first = box * 6 + 1;
            int row = bit(bits48, first) << 1 | bit(bits48, first + 5);
            int column = bit(bits48, first + 1) << 3 | bit(bits48, first + 2) << 2
                    | bit(bits48, first + 3) << 1 | bit(bits48, first + 4);
            int value = DesTables.S[box][row][column];
            for (int i = 0; i < 4; i++) {
                setBit(out, box * 4 + 1 + i, value >> (3 - i) & 1);
            }
        }
        return out;
    }

    /** Output bit n is input bit table[n-1]. The output has table.length bits. */
    static byte[] permute(byte[] input, int[] table) {
        byte[] out = new byte[(table.length + 7) / 8];
        for (int i = 0; i < table.length; i++) {
            setBit(out, i + 1, bit(input, table[i]));
        }
        return out;
    }

    /** Rotates C (bits 1-28) and D (bits 29-56) left separately, by building the matching permutation. */
    private static byte[] rotateHalvesLeft(byte[] cd, int by) {
        int[] table = new int[56];
        for (int i = 0; i < 28; i++) {
            table[i] = (i + by) % 28 + 1;
            table[28 + i] = 28 + (i + by) % 28 + 1;
        }
        return permute(cd, table);
    }

    /** Bit number n (from 1, leftmost first) of the data. */
    private static int bit(byte[] data, int n) {
        return data[(n - 1) / 8] >> (7 - (n - 1) % 8) & 1;
    }

    private static void setBit(byte[] data, int n, int value) {
        int index = (n - 1) / 8;
        int mask = 1 << (7 - (n - 1) % 8);
        data[index] = (byte) (value == 1 ? data[index] | mask : data[index] & ~mask);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] joined = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, joined, a.length, b.length);
        return joined;
    }

    private static final class Recorder {
        final List<DesSteps.Round> rounds;
        final String[] summary;

        Recorder(List<DesSteps.Round> rounds, String[] summary) {
            this.rounds = rounds;
            this.summary = summary;
        }
    }
}
