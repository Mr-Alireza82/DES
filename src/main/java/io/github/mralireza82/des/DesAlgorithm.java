package io.github.mralireza82.des;

/** Which algorithm a {@link DesCipher} or {@link SimpleDesCipher} runs on each block. */
public enum DesAlgorithm {
    /** Single DES: 8-byte key. Broken today; legacy systems only. */
    DES("DES"),
    /** Triple DES, encrypt-decrypt-encrypt: 16-byte (K1 K2 K1) or 24-byte (K1 K2 K3) key. */
    TRIPLE_DES("DESede");

    private final String javaName;

    DesAlgorithm(String javaName) {
        this.javaName = javaName;
    }

    /** The name Java's {@code javax.crypto} uses for this algorithm. */
    String javaName() {
        return javaName;
    }

    /** Checks the key length for this algorithm. */
    void requireKey(byte[] key) {
        if (this == DES) {
            DesKeys.requireSingleKey(key);
        } else {
            DesKeys.tripleParts(key);
        }
    }
}
