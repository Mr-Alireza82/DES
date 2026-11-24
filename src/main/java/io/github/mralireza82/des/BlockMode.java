package io.github.mralireza82.des;

/**
 * How the blocks of a longer message are connected (mode of operation, NIST SP 800-38A).
 */
public enum BlockMode {
    /**
     * Electronic Codebook: every block is encrypted on its own. No IV. Equal input blocks give equal output
     * blocks, so it is only safe for single random-looking blocks such as PIN blocks and keys.
     */
    ECB,
    /**
     * Cipher Block Chaining: each block is XORed with the previous encrypted block before it is encrypted;
     * the first block is XORed with the 8-byte IV. Used for messages and for the Retail MAC.
     */
    CBC;

    /** True if this mode needs an initialization vector. */
    public boolean needsIv() {
        return this == CBC;
    }
}
