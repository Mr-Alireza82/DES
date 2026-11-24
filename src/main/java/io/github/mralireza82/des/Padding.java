package io.github.mralireza82.des;

import java.util.Arrays;
import java.util.Objects;

/**
 * How data is filled up to a whole number of 8-byte blocks before encryption, and emptied again after
 * decryption.
 */
public enum Padding {
    /** No padding: the data must already be a multiple of 8 bytes. */
    NONE,
    /**
     * ISO/IEC 9797-1 padding method 1 (zero padding): add {@code 00} bytes until the length is a multiple of
     * 8; nothing is added if it already is (empty data becomes one zero block). It cannot be removed
     * reliably, because the data itself may end with zeros, so decryption returns the padded data.
     */
    ISO_9797_1_METHOD_1,
    /**
     * ISO/IEC 9797-1 padding method 2: always add one {@code 80} byte, then {@code 00} bytes up to a multiple
     * of 8. Can always be removed.
     */
    ISO_9797_1_METHOD_2,
    /** PKCS #7 (same as PKCS #5 for 8-byte blocks): add N bytes of value N, N = 1 to 8. Can always be removed. */
    PKCS7;

    private static final int BLOCK = DesKeys.BLOCK_SIZE;

    /** The data filled up to whole blocks. The input is not changed. */
    public byte[] pad(byte[] data) {
        Objects.requireNonNull(data, "data");
        switch (this) {
            case NONE:
                if (data.length % BLOCK != 0) {
                    throw new IllegalArgumentException("without padding the data must be a multiple of 8 bytes, got "
                            + data.length + " (choose a padding)");
                }
                return data.clone();
            case ISO_9797_1_METHOD_1: {
                int length = data.length == 0 ? BLOCK : roundUp(data.length);
                return Arrays.copyOf(data, length);
            }
            case ISO_9797_1_METHOD_2: {
                byte[] padded = Arrays.copyOf(data, roundUp(data.length + 1));
                padded[data.length] = (byte) 0x80;
                return padded;
            }
            case PKCS7: {
                int count = BLOCK - data.length % BLOCK;
                byte[] padded = Arrays.copyOf(data, data.length + count);
                Arrays.fill(padded, data.length, padded.length, (byte) count);
                return padded;
            }
            default:
                throw new IllegalStateException("unknown padding " + this);
        }
    }

    /** The original data without its padding. Method 1 cannot be undone and returns the data unchanged. */
    public byte[] unpad(byte[] padded) {
        Objects.requireNonNull(padded, "padded");
        switch (this) {
            case NONE:
            case ISO_9797_1_METHOD_1:
                return padded.clone();
            case ISO_9797_1_METHOD_2: {
                int end = padded.length - 1;
                while (end >= 0 && padded[end] == 0) {
                    end--;
                }
                if (end < 0 || padded[end] != (byte) 0x80 || padded.length - end > BLOCK) {
                    throw new IllegalArgumentException("not valid ISO 9797-1 method 2 padding (wrong key or IV?)");
                }
                return Arrays.copyOf(padded, end);
            }
            case PKCS7: {
                int count = padded.length == 0 ? 0 : padded[padded.length - 1];
                boolean valid = count >= 1 && count <= BLOCK && count <= padded.length;
                for (int i = padded.length - count; valid && i < padded.length; i++) {
                    valid = padded[i] == count;
                }
                if (!valid) {
                    throw new IllegalArgumentException("not valid PKCS #7 padding (wrong key or IV?)");
                }
                return Arrays.copyOf(padded, padded.length - count);
            }
            default:
                throw new IllegalStateException("unknown padding " + this);
        }
    }

    private static int roundUp(int length) {
        return (length + BLOCK - 1) / BLOCK * BLOCK;
    }
}
