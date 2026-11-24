package io.github.mralireza82.des;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * DES and Triple DES, the standard way: the Java platform's own implementation ({@code javax.crypto}).
 * Use this one in real code. Each call encrypts or decrypts exactly one 8-byte block (ECB, no padding);
 * modes such as CBC and padding are built on top by the caller (for example the Retail MAC).
 * {@link SimpleDes} computes the same results bit by bit with the FIPS 46-3 tables, for learning.
 *
 * <p>Triple DES is EDE: {@code E(K3, D(K2, E(K1, block)))}. A 16-byte key means K3 = K1; a 24-byte key
 * gives all three. With K1 = K2 = K3 it equals single DES.
 */
public final class Des {
    private Des() {
    }

    /** Encrypts one 8-byte block with an 8-byte key. */
    public static byte[] encrypt(byte[] key, byte[] block) {
        DesKeys.requireSingleKey(key);
        return run("DES", Cipher.ENCRYPT_MODE, key, block);
    }

    /** Decrypts one 8-byte block with an 8-byte key. */
    public static byte[] decrypt(byte[] key, byte[] block) {
        DesKeys.requireSingleKey(key);
        return run("DES", Cipher.DECRYPT_MODE, key, block);
    }

    /** Triple DES encryption of one block with a 16- or 24-byte key. */
    public static byte[] encryptTriple(byte[] key, byte[] block) {
        return run("DESede", Cipher.ENCRYPT_MODE, DesKeys.threeKeyForm(key), block);
    }

    /** Triple DES decryption of one block with a 16- or 24-byte key. */
    public static byte[] decryptTriple(byte[] key, byte[] block) {
        return run("DESede", Cipher.DECRYPT_MODE, DesKeys.threeKeyForm(key), block);
    }

    private static byte[] run(String algorithm, int mode, byte[] key, byte[] block) {
        DesKeys.requireBlock(block);
        try {
            Cipher cipher = Cipher.getInstance(algorithm + "/ECB/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, algorithm));
            return cipher.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithm + " is not available on this Java platform", e);
        }
    }
}
