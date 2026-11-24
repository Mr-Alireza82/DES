package io.github.mralireza82.des;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * Encrypts and decrypts whole messages with DES or Triple DES, the standard way: padding by
 * {@link Padding}, then Java's own {@code javax.crypto} for the blocks and the chaining. Use this one in real
 * code. {@link SimpleDesCipher} does the same with every step visible.
 *
 * <pre>{@code
 * DesCipher cipher = DesCipher.of(DesAlgorithm.TRIPLE_DES, BlockMode.CBC, Padding.ISO_9797_1_METHOD_2);
 * byte[] encrypted = cipher.encrypt(key, iv, data);
 * byte[] plain     = cipher.decrypt(key, iv, encrypted);
 * }</pre>
 *
 * ECB takes no IV ({@code encrypt(key, data)}); CBC needs one ({@code encrypt(key, iv, data)}). Inputs are
 * never changed. Instances are immutable and thread-safe.
 */
public final class DesCipher {
    private final DesAlgorithm algorithm;
    private final BlockMode mode;
    private final Padding padding;

    private DesCipher(DesAlgorithm algorithm, BlockMode mode, Padding padding) {
        CipherChecks.requireSettings(algorithm, mode, padding);
        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
    }

    public static DesCipher of(DesAlgorithm algorithm, BlockMode mode, Padding padding) {
        return new DesCipher(algorithm, mode, padding);
    }

    public DesAlgorithm algorithm() {
        return algorithm;
    }

    public BlockMode mode() {
        return mode;
    }

    public Padding padding() {
        return padding;
    }

    /** ECB: pads, then encrypts every block on its own. */
    public byte[] encrypt(byte[] key, byte[] data) {
        return encrypt(key, null, data);
    }

    /** ECB: decrypts every block on its own, then removes the padding. */
    public byte[] decrypt(byte[] key, byte[] data) {
        return decrypt(key, null, data);
    }

    /** CBC: pads, then encrypts with chaining that starts from the IV. */
    public byte[] encrypt(byte[] key, byte[] iv, byte[] data) {
        CipherChecks.requireInputs(algorithm, mode, key, iv, data);
        return run(Cipher.ENCRYPT_MODE, key, iv, padding.pad(data));
    }

    /** CBC: decrypts with chaining that starts from the IV, then removes the padding. */
    public byte[] decrypt(byte[] key, byte[] iv, byte[] data) {
        CipherChecks.requireInputs(algorithm, mode, key, iv, data);
        CipherChecks.requireWholeBlocks(data);
        return padding.unpad(run(Cipher.DECRYPT_MODE, key, iv, data));
    }

    private byte[] run(int direction, byte[] key, byte[] iv, byte[] blocks) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm.javaName() + "/" + mode + "/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(javaKey(key), algorithm.javaName());
            if (iv == null) {
                cipher.init(direction, keySpec);
            } else {
                cipher.init(direction, keySpec, new IvParameterSpec(iv));
            }
            return cipher.doFinal(blocks);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithm + "/" + mode + " is not available on this Java platform", e);
        }
    }

    private byte[] javaKey(byte[] key) {
        return algorithm == DesAlgorithm.DES ? key : DesKeys.threeKeyForm(key);
    }
}
