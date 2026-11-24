package io.github.mralireza82.des;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static io.github.mralireza82.baseconversion.ByteEncoding.fromHex;
import static io.github.mralireza82.baseconversion.ByteEncoding.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Modes and padding: FIPS 81 vectors, the Retail MAC chaining, padding rules, and both ways compared. */
class DesCipherTest {
    // FIPS PUB 81, Appendix B: "Now is the time for all " under key 0123456789ABCDEF.
    private static final byte[] FIPS_KEY = fromHex("0123456789ABCDEF");
    private static final byte[] FIPS_IV = fromHex("1234567890ABCDEF");
    private static final byte[] FIPS_TEXT = "Now is the time for all ".getBytes(StandardCharsets.US_ASCII);

    @Test
    void fips81Ecb() {
        String expected = "3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53";
        assertEquals(expected, toHex(DesCipher.of(DesAlgorithm.DES, BlockMode.ECB, Padding.NONE).encrypt(FIPS_KEY, FIPS_TEXT)));
        assertEquals(expected, toHex(SimpleDesCipher.of(DesAlgorithm.DES, BlockMode.ECB, Padding.NONE).encrypt(FIPS_KEY, FIPS_TEXT)));
    }

    @Test
    void fips81Cbc() {
        String expected = "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6";
        DesCipher standard = DesCipher.of(DesAlgorithm.DES, BlockMode.CBC, Padding.NONE);
        SimpleDesCipher paper = SimpleDesCipher.of(DesAlgorithm.DES, BlockMode.CBC, Padding.NONE);

        assertEquals(expected, toHex(standard.encrypt(FIPS_KEY, FIPS_IV, FIPS_TEXT)));
        assertEquals(expected, toHex(paper.encrypt(FIPS_KEY, FIPS_IV, FIPS_TEXT)));
        assertArrayEquals(FIPS_TEXT, standard.decrypt(FIPS_KEY, FIPS_IV, fromHex(expected)));
        assertArrayEquals(FIPS_TEXT, paper.decrypt(FIPS_KEY, FIPS_IV, fromHex(expected)));
    }

    @Test
    void retailMacChainingIsCbcWithZeroIvAndMethod1() {
        byte[] message = "PAYMENT123".getBytes(StandardCharsets.US_ASCII);
        byte[] k1 = fromHex("0123456789ABCDEF");
        byte[] encrypted = DesCipher.of(DesAlgorithm.DES, BlockMode.CBC, Padding.ISO_9797_1_METHOD_1)
                .encrypt(k1, new byte[8], message);

        // The two chaining values H1 and H2 of the ANSI X9.19 Retail MAC article.
        assertEquals("355227E11D967D54775332C133888CD3", toHex(encrypted));
    }

    @ParameterizedTest(name = "{0} of {1}")
    @CsvSource({
            "ISO_9797_1_METHOD_1, '',                 0000000000000000",
            "ISO_9797_1_METHOD_1, 5041594D454E5431,   5041594D454E5431",
            "ISO_9797_1_METHOD_1, 5041594D454E543132, 5041594D454E54313200000000000000",
            "ISO_9797_1_METHOD_2, '',                 8000000000000000",
            "ISO_9797_1_METHOD_2, 5041594D454E5431,   5041594D454E54318000000000000000",
            "ISO_9797_1_METHOD_2, 50415900,           5041590080000000",
            "PKCS7,               '',                 0808080808080808",
            "PKCS7,               5041594D454E54,     5041594D454E5401",
            "PKCS7,               5041594D454E5431,   5041594D454E54310808080808080808",
    })
    void paddingRules(Padding padding, String data, String padded) {
        assertEquals(padded, toHex(padding.pad(fromHex(data))));
        if (padding != Padding.ISO_9797_1_METHOD_1) {
            assertEquals(data, toHex(padding.unpad(fromHex(padded))));
        }
    }

    @Test
    void bothWaysAgreeForEveryCombination() {
        Random random = new Random(81);
        for (DesAlgorithm algorithm : DesAlgorithm.values()) {
            for (BlockMode mode : BlockMode.values()) {
                for (Padding padding : Padding.values()) {
                    for (int round = 0; round < 20; round++) {
                        byte[] key = bytes(random, algorithm == DesAlgorithm.DES ? 8 : (round % 2 == 0 ? 16 : 24));
                        byte[] iv = mode.needsIv() ? bytes(random, 8) : null;
                        byte[] data = bytes(random, padding == Padding.NONE ? 8 * random.nextInt(5) : random.nextInt(40));
                        DesCipher standard = DesCipher.of(algorithm, mode, padding);
                        SimpleDesCipher paper = SimpleDesCipher.of(algorithm, mode, padding);

                        byte[] encrypted = standard.encrypt(key, iv, data);
                        assertArrayEquals(encrypted, paper.encrypt(key, iv, data), algorithm + "/" + mode + "/" + padding);
                        byte[] back = padding == Padding.ISO_9797_1_METHOD_1 ? padding.pad(data) : data;
                        assertArrayEquals(back, standard.decrypt(key, iv, encrypted));
                        assertArrayEquals(back, paper.decrypt(key, iv, encrypted));
                    }
                }
            }
        }
    }

    @Test
    void ecbShowsRepeatedBlocksAndCbcHidesThem() {
        byte[] twoEqualBlocks = fromHex("041225EEEEEEEEEE041225EEEEEEEEEE");
        byte[] key = fromHex("0123456789ABCDEFFEDCBA9876543210");
        byte[] ecb = DesCipher.of(DesAlgorithm.TRIPLE_DES, BlockMode.ECB, Padding.NONE).encrypt(key, twoEqualBlocks);
        byte[] cbc = DesCipher.of(DesAlgorithm.TRIPLE_DES, BlockMode.CBC, Padding.NONE).encrypt(key, new byte[8], twoEqualBlocks);

        assertEquals(toHex(ecb).substring(0, 16), toHex(ecb).substring(16));
        assertEquals("2A3D408A1977DDE9", toHex(ecb).substring(0, 16));
        assertEquals(toHex(ecb).substring(0, 16), toHex(cbc).substring(0, 16));
        assertEquals(false, toHex(cbc).substring(0, 16).equals(toHex(cbc).substring(16)));
    }

    @Test
    void wrongInputsAreRejected() {
        DesCipher cbc = DesCipher.of(DesAlgorithm.DES, BlockMode.CBC, Padding.PKCS7);
        DesCipher ecb = DesCipher.of(DesAlgorithm.DES, BlockMode.ECB, Padding.PKCS7);
        DesCipher tdes = DesCipher.of(DesAlgorithm.TRIPLE_DES, BlockMode.ECB, Padding.NONE);
        SimpleDesCipher paperCbc = SimpleDesCipher.of(DesAlgorithm.DES, BlockMode.CBC, Padding.PKCS7);

        assertThrows(IllegalArgumentException.class, () -> cbc.encrypt(new byte[8], new byte[3]));
        assertThrows(IllegalArgumentException.class, () -> paperCbc.encrypt(new byte[8], new byte[3]));
        assertThrows(IllegalArgumentException.class, () -> ecb.encrypt(new byte[8], new byte[8], new byte[3]));
        assertThrows(IllegalArgumentException.class, () -> cbc.encrypt(new byte[8], new byte[7], new byte[3]));
        assertThrows(IllegalArgumentException.class, () -> tdes.encrypt(new byte[8], new byte[8]));
        assertThrows(IllegalArgumentException.class, () -> tdes.encrypt(new byte[16], new byte[7]));
        assertThrows(IllegalArgumentException.class, () -> ecb.decrypt(new byte[8], new byte[9]));
        assertThrows(IllegalArgumentException.class, () -> Padding.PKCS7.unpad(fromHex("0102030405060709")));
        assertThrows(IllegalArgumentException.class, () -> Padding.ISO_9797_1_METHOD_2.unpad(new byte[8]));
    }

    private static byte[] bytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
