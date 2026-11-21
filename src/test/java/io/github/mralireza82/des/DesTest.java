package io.github.mralireza82.des;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Random;

import static io.github.mralireza82.baseconversion.ByteEncoding.fromHex;
import static io.github.mralireza82.baseconversion.ByteEncoding.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Known answers from the literature, the Retail MAC article, and both ways compared on random data. */
class DesTest {

    @ParameterizedTest(name = "DES({0}, {1}) = {2}")
    @CsvSource({
            // The classic worked example (J. O. Grabbe, "The DES Algorithm Illustrated").
            "133457799BBCDFF1, 0123456789ABCDEF, 85E813540F0AB405",
            // Encrypting zeros with this key gives its key check value D5D44F.
            "0123456789ABCDEF, 0000000000000000, D5D44FF720683D0D",
            // The ANSI X9.19 Retail MAC article, steps 3 and 4.
            "0123456789ABCDEF, 5041594D454E5431, 355227E11D967D54",
            "0123456789ABCDEF, 076127E11D967D54, 775332C133888CD3",
            "0123456789ABCDEF, 5686442BF278651D, 89FA1AAA2C6E27ED",
    })
    void knownAnswers(String key, String plain, String cipher) {
        assertEquals(cipher, toHex(Des.encrypt(fromHex(key), fromHex(plain))));
        assertEquals(cipher, toHex(SimpleDes.encrypt(fromHex(key), fromHex(plain))));
        assertEquals(plain, toHex(Des.decrypt(fromHex(key), fromHex(cipher))));
        assertEquals(plain, toHex(SimpleDes.decrypt(fromHex(key), fromHex(cipher))));
    }

    @Test
    void retailMacFinalDecryptionStep() {
        byte[] k2 = fromHex("FEDCBA9876543210");
        assertEquals("5686442BF278651D", toHex(SimpleDes.decrypt(k2, fromHex("775332C133888CD3"))));
        assertEquals("5686442BF278651D", toHex(Des.decrypt(k2, fromHex("775332C133888CD3"))));
    }

    @Test
    void stepsMatchTheWorkedExample() {
        DesSteps steps = SimpleDes.encryptWithSteps(fromHex("133457799BBCDFF1"), fromHex("0123456789ABCDEF"));

        assertEquals("F0CCAAF556678F", steps.keyAfterPc1());
        assertEquals("1B02EFFC7072", steps.roundKeys().get(0));
        assertEquals("CB3D8B0E17F5", steps.roundKeys().get(15));
        assertEquals("CC00CCFFF0AAF0AA", steps.afterIp());
        assertEquals("F0AAF0AA", steps.rounds().get(0).left());
        assertEquals("EF4A6544", steps.rounds().get(0).right());
        assertEquals("43423234", steps.rounds().get(15).left());
        assertEquals("0A4CD995", steps.rounds().get(15).right());
        assertEquals("0A4CD99543423234", steps.beforeFp());
        assertEquals("85E813540F0AB405", steps.output());
        assertEquals(16, steps.rounds().size());
    }

    @Test
    void bothWaysAgreeOnRandomData() {
        Random random = new Random(46);
        for (int round = 0; round < 300; round++) {
            byte[] key = bytes(random, 8);
            byte[] key16 = bytes(random, 16);
            byte[] key24 = bytes(random, 24);
            byte[] block = bytes(random, 8);

            assertArrayEquals(Des.encrypt(key, block), SimpleDes.encrypt(key, block));
            assertArrayEquals(Des.decrypt(key, block), SimpleDes.decrypt(key, block));
            assertArrayEquals(Des.encryptTriple(key16, block), SimpleDes.encryptTriple(key16, block));
            assertArrayEquals(Des.encryptTriple(key24, block), SimpleDes.encryptTriple(key24, block));
            assertArrayEquals(Des.decryptTriple(key24, block), SimpleDes.decryptTriple(key24, block));
            assertArrayEquals(block, SimpleDes.decrypt(key, SimpleDes.encrypt(key, block)));
            assertArrayEquals(block, Des.decryptTriple(key16, Des.encryptTriple(key16, block)));
        }
    }

    @Test
    void tripleDesWithOneKeyRepeatedIsSingleDes() {
        byte[] key = fromHex("0123456789ABCDEF");
        byte[] block = fromHex("5041594D454E5431");
        byte[] same = fromHex("0123456789ABCDEF0123456789ABCDEF");

        assertArrayEquals(Des.encrypt(key, block), Des.encryptTriple(same, block));
        assertArrayEquals(Des.encrypt(key, block), SimpleDes.encryptTriple(same, block));
    }

    @Test
    void doubleLengthKeyIsK1K2K1() {
        byte[] block = fromHex("041225EEEEEEEEEE");
        assertArrayEquals(
                Des.encryptTriple(fromHex("0123456789ABCDEFFEDCBA98765432100123456789ABCDEF"), block),
                Des.encryptTriple(fromHex("0123456789ABCDEFFEDCBA9876543210"), block));
    }

    @Test
    void parityAndCheckValue() {
        assertTrue(DesKeys.hasOddParity(fromHex("0123456789ABCDEF")));
        assertFalse(DesKeys.hasOddParity(fromHex("0022446688AACCEE")));
        assertEquals("0123456789ABCDEF", toHex(DesKeys.withOddParity(fromHex("0022446688AACCEE"))));
        assertEquals("D5D44F", toHex(DesKeys.checkValue(fromHex("0123456789ABCDEF"))));
        // The parity bits are not used: changing them changes nothing.
        assertArrayEquals(Des.encrypt(fromHex("0123456789ABCDEF"), new byte[8]),
                SimpleDes.encrypt(fromHex("0022446688AACCEE"), new byte[8]));
    }

    @Test
    void wrongSizesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> Des.encrypt(new byte[7], new byte[8]));
        assertThrows(IllegalArgumentException.class, () -> Des.encrypt(new byte[8], new byte[9]));
        assertThrows(IllegalArgumentException.class, () -> SimpleDes.encrypt(new byte[8], new byte[7]));
        assertThrows(IllegalArgumentException.class, () -> Des.encryptTriple(new byte[8], new byte[8]));
        assertThrows(IllegalArgumentException.class, () -> SimpleDes.encryptTriple(new byte[20], new byte[8]));
    }

    private static byte[] bytes(Random random, int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
